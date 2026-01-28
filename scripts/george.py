#!/usr/bin/env python3
"""
George Banking Automation - Erste Bank/Sparkasse Austria

Modular script for:
- Listing accounts
- Downloading PDF statements (with booking receipts)
- Downloading data exports (CAMT53/MT940)
- Downloading transaction exports (CSV/JSON/OFX/XLSX)

Requires phone approval via George app during login.
"""

import sys
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

import argparse
import json
import os
import re
import subprocess
import time
from datetime import datetime, date, timedelta
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, parse_qsl


def _load_dotenv(path: Path) -> None:
    """Best-effort .env loader (KEY=VALUE lines)."""
    try:
        if not path.exists():
            return
        for line in path.read_text().splitlines():
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v
    except Exception:
        return


# Fast path: allow `--help` without requiring Playwright.
if "-h" in sys.argv or "--help" in sys.argv:
    sync_playwright = None  # type: ignore[assignment]
    PlaywrightTimeout = Exception  # type: ignore[assignment]
else:
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
    except ImportError:
        print("ERROR: playwright not installed. Run: pipx install playwright && playwright install chromium")
        sys.exit(1)

def _default_state_dir() -> Path:
    return Path.home() / ".clawdbot" / "george"


# Runtime state dir (override via --dir or GEORGE_DIR)
STATE_DIR: Path = _default_state_dir()
CONFIG_PATH: Path = STATE_DIR / "config.json"
PROFILE_DIR: Path = STATE_DIR / ".pw-profile"
DEFAULT_OUTPUT_DIR: Path = STATE_DIR / "data"

DEBUG_DIR: Path = STATE_DIR / "debug"
TOKEN_CACHE_FILE: Path = PROFILE_DIR / "token.json"

DEFAULT_LOGIN_TIMEOUT = 60  # seconds

# User id override for this run (set from CLI --user-id)
USER_ID_OVERRIDE: str | None = None

# George URLs
BASE_URL = "https://george.sparkasse.at"
LOGIN_URL = f"{BASE_URL}/index.html#/login"
DASHBOARD_URL = f"{BASE_URL}/index.html#/overview"


def _is_login_flow_url(url: str) -> bool:
    """Return True if URL looks like any login/SSO/OAuth page."""
    u = (url or "").lower()
    return (
        "login.sparkasse.at" in u
        or "/sts/oauth/authorize" in u
        or "#/login" in u
        or u.endswith("/login")
        or "/login" in u
    )


def _is_george_app_url(url: str) -> bool:
    u = (url or "").lower()
    return "george.sparkasse.at" in u


def _extract_token_expires_in_seconds(url: str | None) -> int | None:
    """Return expires_in seconds if the URL fragment includes an OAuth token response."""
    if not url:
        return None
    try:
        parts = urlsplit(url)
        frag = parts.fragment or ""
        if "access_token=" not in frag and "id_token=" not in frag:
            return None
        qs = dict(parse_qsl(frag, keep_blank_values=True))
        ei = qs.get("expires_in")
        return int(ei) if ei and ei.isdigit() else None
    except Exception:
        return None


def _safe_url_for_logs(url: str | None) -> str:
    """Redact sensitive info from URLs before logging.

    George sometimes returns OAuth tokens in the URL fragment, e.g.
    `index.html#access_token=...&expires_in=...&state=/overview...`.
    Never log those tokens.
    """
    if not url:
        return "<empty>"

    try:
        parts = urlsplit(url)
        frag = parts.fragment or ""
        if "access_token=" in frag or "id_token=" in frag or "refresh_token=" in frag:
            qs = dict(parse_qsl(frag, keep_blank_values=True))
            state = qs.get("state")
            expires_in = qs.get("expires_in")
            # Keep only non-sensitive debugging info
            safe_frag_bits = []
            if state:
                safe_frag_bits.append(f"state={state}")
            if expires_in:
                safe_frag_bits.append(f"expires_in={expires_in}")
            safe_frag = "&".join(safe_frag_bits) if safe_frag_bits else "<redacted>"
            return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, safe_frag))

        # Otherwise keep the URL as-is
        return url
    except Exception:
        # Last resort: coarse redaction
        return "<redacted-url>"


def _apply_state_dir(dir_value: str | None) -> None:
    """Apply state dir override and recompute derived paths."""
    global STATE_DIR, CONFIG_PATH, PROFILE_DIR, DEFAULT_OUTPUT_DIR

    if dir_value:
        STATE_DIR = Path(dir_value).expanduser().resolve()
    else:
        env_dir = os.environ.get("GEORGE_DIR")
        STATE_DIR = Path(env_dir).expanduser().resolve() if env_dir else _default_state_dir()

    CONFIG_PATH = STATE_DIR / "config.json"
    PROFILE_DIR = STATE_DIR / ".pw-profile"
    DEFAULT_OUTPUT_DIR = STATE_DIR / "data"

    global DEBUG_DIR, TOKEN_CACHE_FILE
    DEBUG_DIR = STATE_DIR / "debug"
    TOKEN_CACHE_FILE = PROFILE_DIR / "token.json"

    # Load optional .env from the state dir.
    _load_dotenv(STATE_DIR / ".env")



def _now_iso_local() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _write_debug_json(prefix: str, payload) -> Path:
    # Write bank-native payload to a timestamped JSON file for debugging.
    _ensure_dir(DEBUG_DIR)
    ts = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    out = DEBUG_DIR / f"{ts}-{prefix}.json"
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2))
    return out


def _load_token_cache() -> dict | None:
    try:
        if not TOKEN_CACHE_FILE.exists():
            return None
        return json.loads(TOKEN_CACHE_FILE.read_text())
    except Exception:
        return None


def _save_token_cache(access_token: str, source: str = "auth_header", expires_at: str | None = None) -> None:
    try:
        _ensure_dir(TOKEN_CACHE_FILE.parent)
        data = {
            "accessToken": access_token,
            "obtainedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expiresAt": expires_at,
            "source": source,
        }
        TOKEN_CACHE_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2))
    except Exception:
        return


def _extract_bearer_token(auth_header: str) -> str | None:
    if not auth_header:
        return None
    m = re.match(r"(?i)bearer\s+(.+)$", auth_header.strip())
    if not m:
        return None
    return m.group(1).strip()


def _eu_amount(amount: float | None) -> str:
    if amount is None:
        return "N/A"
    s = f"{amount:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    return s


def _canonical_account_type_george(raw_type: str | None) -> str:
    t = (raw_type or "").lower()
    return {
        "currentaccount": "checking",
        "current": "checking",
        "giro": "checking",
        "saving": "savings",
        "savings": "savings",
        "loan": "loan",
        "credit": "credit",
        "kredit": "credit",
        "creditcard": "creditcard",
    }.get(t, t or "other")


def canonicalize_accounts_george(payload, normalized: list[dict], raw_path: Path | None = None) -> dict:
    # Build canonical accounts wrapper for George.
    raw_accounts: list[dict] = []
    if isinstance(payload, list):
        raw_accounts = [x for x in payload if isinstance(x, dict)]
    elif isinstance(payload, dict):
        for key in ("items", "accounts", "data", "content", "accountList"):
            v = payload.get(key)
            if isinstance(v, list):
                raw_accounts = [x for x in v if isinstance(x, dict)]
                break

    by_id: dict[str, dict] = {}
    for acc in raw_accounts:
        acc_id = _extract_first(acc, ["id", "accountId", "uid", "uuid"])
        if acc_id is not None:
            by_id[str(acc_id)] = acc

    out_accounts = []
    for a in normalized:
        acc_id = str(a.get("id") or "")
        raw = by_id.get(acc_id) or {}

        bal_amt, bal_ccy = _extract_money_from_account(
            raw,
            ["balance", "accountBalance", "amount", "currentBalance", "value"],
            ["currency", "ccy"],
        )
        avail_amt, avail_ccy = _extract_money_from_account(
            raw,
            ["disposable", "disposableAmount", "available", "availableAmount", "disposableBalance"],
            ["currency", "ccy"],
        )
        if avail_ccy is None:
            avail_ccy = bal_ccy

        currency = (a.get("currency") or bal_ccy or avail_ccy or "EUR").strip()

        acct = {
            "id": acc_id,
            "type": _canonical_account_type_george(a.get("type")),
            "name": a.get("name") or a.get("alias") or a.get("description") or "N/A",
            "iban": a.get("iban"),
            "currency": currency,
            "balances": {
                "booked": {"amount": bal_amt, "currency": currency} if bal_amt is not None else None,
                "available": {"amount": avail_amt, "currency": currency} if avail_amt is not None else None,
            },
        }
        out_accounts.append(acct)

    return {
        "institution": "george",
        "fetchedAt": _now_iso_local(),
        "rawPath": str(raw_path) if raw_path else None,
        "accounts": out_accounts,
    }

def _login_timeout(args) -> int:
    return getattr(args, "login_timeout", DEFAULT_LOGIN_TIMEOUT)

def load_config() -> dict:
    """Load configuration from JSON file.

    Supports automatic migration from older formats.
    """
    if not CONFIG_PATH.exists():
        print(f"ERROR: Config file not found at {CONFIG_PATH}")
        print("Please create it with your 'user_id' and 'accounts'.")
        sys.exit(1)

    with open(CONFIG_PATH, "r") as f:
        cfg = json.load(f)

    # Normalize + migrate accounts structure.
    # New format: accounts is a list of account dicts.
    accs = cfg.get("accounts")
    if accs is None:
        cfg["accounts"] = []
    elif isinstance(accs, dict):
        # Old format: { key: {account...}, ... }
        cfg["accounts"] = list(accs.values())
    elif isinstance(accs, list):
        pass
    else:
        raise ValueError("config.json: 'accounts' must be a list (preferred) or dict (legacy)")

    # user_id can be string (preferred) or list (legacy-ish)
    uid = cfg.get("user_id")
    if isinstance(uid, list):
        # Keep as-is; resolved later.
        pass
    elif uid is None:
        # allowed; resolved later.
        pass
    elif not isinstance(uid, str):
        raise ValueError("config.json: 'user_id' must be a string or a list of strings")

    return cfg

def save_config(config: dict) -> None:
    """Write config to disk (creates parent dirs)."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    # Ensure accounts is always a list on disk.
    accs = config.get("accounts")
    if accs is None:
        config["accounts"] = []
    elif isinstance(accs, dict):
        config["accounts"] = list(accs.values())

    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=4, sort_keys=True)


_ACCOUNT_TYPE_PREFIX = {
    "currentaccount": "current",
    "currentaccount": "current",
    "saving": "saving",
    "loan": "loan",
    "credit": "credit",
    "kredit": "credit",
    "creditcard": "cc",
}


def _slug(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s or "account"


def _suggest_account_key(acc: dict, existing: set[str]) -> str:
    """Create a stable, human-usable account key for config.json.

    Prefer a name-based key (for readability) with a short suffix for uniqueness.
    """
    name = _slug(acc.get("name") or "")

    # Keep keys reasonably short
    name = name[:24]

    iban = (acc.get("iban") or "")
    iban_clean = re.sub(r"\s+", "", iban)
    suffix = iban_clean[-4:] if len(iban_clean) >= 4 else str(acc.get("id") or "")[-6:]
    suffix = suffix or "0000"

    base = f"{name}-{suffix}".lower()

    # If that base already exists, fall back to type-based base.
    if base in existing:
        acc_type = (acc.get("type") or "account").lower()
        prefix = _ACCOUNT_TYPE_PREFIX.get(acc_type, acc_type)
        base = f"{prefix}-{suffix}".lower()

    key = base
    i = 2
    while key in existing:
        key = f"{base}-{i}".lower()
        i += 1
    return key


def merge_accounts_into_config(config: dict, fetched_accounts: list[dict]) -> tuple[dict, list[str]]:
    """Merge fetched accounts into config['accounts'] (list).

    Returns (updated_config, changed_ids)
    """
    existing: list[dict]
    accs = config.get("accounts")
    if accs is None:
        existing = []
    elif isinstance(accs, dict):
        existing = list(accs.values())
    else:
        existing = list(accs)

    # Index by (type,id)
    by_tid: dict[tuple[str, str], int] = {}
    for idx, a in enumerate(existing):
        t = (a.get("type") or "").lower()
        i = str(a.get("id") or "")
        if t and i:
            by_tid[(t, i)] = idx

    changed: list[str] = []

    for acc in fetched_accounts:
        t = (acc.get("type") or "").lower()
        i = str(acc.get("id") or "")
        if not (t and i):
            continue

        pos = by_tid.get((t, i))
        if pos is not None:
            existing[pos] = {**existing[pos], **acc}
            changed.append(i)
        else:
            existing.append(acc)
            by_tid[(t, i)] = len(existing) - 1
            changed.append(i)

    # Stable-ish sort: type then name
    existing.sort(key=lambda a: ((a.get("type") or ""), (a.get("name") or "")))

    config["accounts"] = existing
    return config, changed


# Load configuration (lazy loaded later to allow help to run without config)
CONFIG = None


def get_account(account_key: str) -> dict:
    """Resolve an account by flexible query.

    Matches by:
    - exact id
    - exact IBAN (spaces ignored)
    - substring match on name
    - substring match on type
    - substring match on IBAN

    If ambiguous, raises with candidates.
    """
    global CONFIG
    if CONFIG is None:
        CONFIG = load_config()

    accounts: list[dict] = CONFIG.get("accounts", []) or []
    q = (account_key or "").strip().lower()

    def iban_norm(s: str | None) -> str:
        return re.sub(r"\s+", "", (s or "")).lower()

    # 1) Exact ID match
    for acc in accounts:
        if (acc.get("id") or "").lower() == q:
            return acc

    # 2) Exact IBAN match
    for acc in accounts:
        if acc.get("iban") and iban_norm(acc.get("iban")) == iban_norm(q):
            return acc

    # 3) Fuzzy matches
    matches: list[dict] = []
    for acc in accounts:
        name = (acc.get("name") or "").lower()
        typ = (acc.get("type") or "").lower()
        if q and (q in name or q in typ or (acc.get("iban") and q in iban_norm(acc.get("iban")))):
            matches.append(acc)

    if len(matches) == 1:
        return matches[0]

    if not matches:
        raise ValueError(f"Unknown account: {account_key}. Run 'accounts' to list known accounts (and fetch if empty).")

    # Ambiguous
    lines = [f"Ambiguous account selector '{account_key}'. Matches:"]
    for acc in matches:
        lines.append(f"- {acc.get('name')} ({acc.get('type')}) id={acc.get('id')}")
    raise ValueError("\n".join(lines))


def wait_for_login_approval(page, timeout_seconds: int = 300) -> bool:
    """Wait for user to approve login on phone.

    Important: do NOT scan the entire HTML for generic phrases (they may exist in hidden UI).
    Only react to **visible** error/dismissal messages.
    """
    print(f"[login] Waiting up to {timeout_seconds}s for phone approval...", flush=True)
    start = time.time()
    last_reported = -1

    dismissed_locator = page.locator("text=The login request was dismissed")
    login_failed_locator = page.locator("text=Login failed")
    login_failed_de_locator = page.locator("text=Anmeldung fehlgeschlagen")

    while time.time() - start < timeout_seconds:
        current_url = page.url

        # Success: redirected back into George app (NOT into the IdP/OAuth page)
        if _is_george_app_url(current_url) and not _is_login_flow_url(current_url):
            # Avoid leading newline + make URL logging robust (some terminals wrap weirdly).
            print(f"[login] Approved! Redirected to: {_safe_url_for_logs(current_url)}", flush=True)

            # Optional: provide a human-friendly "expires at" hint (token expiry, not necessarily cookie session expiry).
            ei = _extract_token_expires_in_seconds(current_url)
            if ei:
                expires_at = datetime.now() + timedelta(seconds=ei)
                print(f"[login] Logged in successfully. Token expires at ~{expires_at:%Y-%m-%d %H:%M:%S}", flush=True)

            return True

        # Do not navigate away here.
        # When George is in the middle of the OAuth/approval flow, extra navigations
        # can restart the redirect chain and make approval look like it "did nothing".

        # Dismissed (user rejected)
        try:
            if dismissed_locator.first.is_visible(timeout=200):
                print("\n[login] ❌ LOGIN DISMISSED - user rejected. Start over.", flush=True)
                return False
        except Exception:
            pass

        # Explicit failure message (visible)
        try:
            if login_failed_locator.first.is_visible(timeout=200) or login_failed_de_locator.first.is_visible(timeout=200):
                print("\n[login] Login failed", flush=True)
                return False
        except Exception:
            pass

        # Progress reporting every 10 seconds
        elapsed = int(time.time() - start)
        interval = elapsed // 10
        if interval > last_reported:
            last_reported = interval
            remaining = timeout_seconds - elapsed
            print(f"[login] Still waiting... {remaining}s remaining (url={_safe_url_for_logs(page.url)})", flush=True)

        time.sleep(1)

    print("\n[login] Script timeout waiting for approval", flush=True)
    return False


def extract_verification_code(page) -> str:
    """Extract verification code from login page."""
    try:
        # Wait for the verification code section to appear
        page.wait_for_selector('text=/Verification code/i', timeout=15000)
        time.sleep(1)  # Give it a moment to fully render
        
        all_text = page.inner_text('body')

        # Look for *the* canonical line: "Verification code: XXXX"
        match = re.search(r'\bVerification code:\s*([A-Z0-9]{4})\b', all_text)
        if match:
            return match.group(1)
        
        # Fallback: scan for a line that exactly matches the format
        for line in all_text.split('\n'):
            m = re.match(r'^Verification code:\s*([A-Z0-9]{4})\s*$', line.strip())
            if m:
                return m.group(1)

        return ""
                    
    except PlaywrightTimeout:
        print("[login] Timeout waiting for verification code element", flush=True)
    except Exception as e:
        print(f"[login] Could not extract verification code: {e}", flush=True)
    return ""


def dismiss_modals(page):
    """Dismiss any modal overlays."""
    try:
        for selector in [
            'button:has-text("Dismiss")',
            'button:has-text("Close")',
            'button:has-text("OK")',
            'button[aria-label="Close"]',
        ]:
            btn = page.query_selector(selector)
            if btn and btn.is_visible():
                print(f"[modal] Dismissing via {selector}", flush=True)
                btn.click()
                time.sleep(0.5)
    except Exception:
        pass


def login(page, timeout_seconds: int = 300) -> bool:
    """Perform George login with phone approval."""
    print("[login] Checking session...", flush=True)
    
    # Try dashboard first to see if session is valid.
    # NOTE: Going to about:blank first improves reliability for some SPA sessions.
    try:
        page.goto("about:blank")
        page.goto(DASHBOARD_URL, wait_until="domcontentloaded", timeout=15000)

        # Fast-path decision:
        # - If the session is expired, George usually redirects to the IdP within a second or two.
        # - If the session is valid, the overview tiles appear.
        tiles_visible = False
        t0 = time.time()
        while time.time() - t0 < 4.0:
            if _is_login_flow_url(page.url):
                break
            try:
                page.wait_for_selector(".g-card-overview-title", timeout=500)
                tiles_visible = True
                break
            except Exception:
                time.sleep(0.2)

        if tiles_visible and _is_george_app_url(page.url) and not _is_login_flow_url(page.url):
            # Extra guard: if the George login form is visible, session is NOT valid.
            login_form_visible = False
            try:
                login_form_visible = page.get_by_role(
                    "button", name=re.compile(r"start login", re.I)
                ).is_visible(timeout=800)
            except Exception:
                login_form_visible = False

            if not login_form_visible:
                print("[login] Session still valid!", flush=True)
                return True
    except Exception:
        pass

    print("[login] Session invalid/expired. Navigating to login...", flush=True)

    # Per observed behavior: always start from the overview and let George redirect
    # into the appropriate login/SSO flow.
    page.goto("about:blank")
    page.goto(DASHBOARD_URL, wait_until="domcontentloaded")

    # Wait for the George login form to appear. If it doesn't show up (e.g. we got
    # stuck at the IdP authorize page), fall back to the explicit /#/login route.
    try:
        # Keep this short: we want to type user_id ASAP.
        page.wait_for_selector('input[aria-label*="User"], input[placeholder*="User"], input', timeout=4000)
    except Exception:
        page.goto("about:blank")
        page.goto(LOGIN_URL, wait_until="domcontentloaded")
        page.wait_for_selector('input', timeout=4000)

    time.sleep(0.2)

    if _is_george_app_url(page.url) and not _is_login_flow_url(page.url):
        print("[login] Already logged in (redirected)!", flush=True)
        return True
    
    print(f"[login] Entering user ID...", flush=True)
    
    global CONFIG
    if CONFIG is None:
        CONFIG = load_config()
        
    try:
        user_id = _resolve_user_id(argparse.Namespace(user_id=USER_ID_OVERRIDE), CONFIG)
    except Exception as e:
        print(f"[login] ERROR: {e}")
        return False

    try:
        page.get_by_role("textbox", name=re.compile(r"user number|username", re.I)).fill(user_id)
    except Exception:
        try:
            page.get_by_role("textbox").first.fill(user_id)
        except Exception:
            page.fill('input', user_id)
    
    time.sleep(1)
    print("[login] Clicking 'Start login'...", flush=True)
    
    try:
        page.get_by_role("button", name="Start login").click()
    except Exception:
        btn = page.query_selector('button:has-text("Start login")')
        if btn:
            btn.click()
        else:
            print("[login] ERROR: Could not find login button", flush=True)
            return False
    
    # George renders the verification code asynchronously.
    # Waiting a bit here makes extraction much more reliable.
    time.sleep(5)
    code = extract_verification_code(page)

    if code:
        print(f"[login] Verification code: {code}", flush=True)
    else:
        print("[login] ⚠️ Could not extract code - CHECK BROWSER WINDOW", flush=True)
    
    # NOTE: No macOS-specific notifications. Code is printed to stdout for the caller
    # (Clawdbot session) to forward via Telegram.
    return wait_for_login_approval(page, timeout_seconds=timeout_seconds)


def _format_iban(iban: str) -> str:
    clean = re.sub(r"\s+", "", iban).strip()
    # Group in blocks of 4 for readability.
    return " ".join(clean[i : i + 4] for i in range(0, len(clean), 4))


def _short_iban(iban: str | None) -> str:
    if not iban:
        return "IBAN N/A"
    clean = re.sub(r"\s+", "", iban).strip()
    if len(clean) <= 8:
        return clean
    return f"{clean[:4]}...{clean[-4:]}"


def _first_iban_in_text(text: str) -> str | None:
    # Standard Austrian IBAN is 20 chars: AT + 18 digits.
    # Note: don't use a word-boundary here; George sometimes concatenates strings like "...KGAT31...".
    m = re.search(r"AT\d{2}(?:\s*\d{4}){4}", text)
    if m:
        return _format_iban(m.group(0))

    # Fallback: permissive, still anchored on AT + digits.
    m2 = re.search(r"AT\d{2}[0-9\s]{16,30}", text)
    if m2:
        return _format_iban(m2.group(0))

    return None


def capture_bearer_auth_header(context, page, timeout_s: int = 10) -> str | None:
    """Capture Bearer Authorization header from any George API request.

    Note: we listen on the *browser context* (not only the page) because George may
    issue requests from background frames / service worker-like contexts.
    """
    auth_header = {"value": None}

    def _on_request(request) -> None:
        if auth_header["value"]:
            return
        try:
            url = request.url or ""
            if not url.startswith("https://api.sparkasse.at/rest/netbanking/"):
                return
            headers = request.headers or {}
            auth = headers.get("authorization") or headers.get("Authorization")
            if auth and auth.lower().startswith("bearer "):
                auth_header["value"] = auth
        except Exception:
            return

    context.on("request", _on_request)
    try:
        # Force a fresh app bootstrap to trigger API calls.
        try:
            page.goto("about:blank")
        except Exception:
            pass

        # Add a cache-buster (before #) to reduce SW/cache short-circuiting.
        bust_url = f"https://george.sparkasse.at/index.html?nocache={int(time.time())}#/overview"
        page.goto(bust_url, wait_until="networkidle")

        start = time.time()
        reloaded = False
        while time.time() - start < timeout_s:
            if auth_header["value"]:
                return auth_header["value"]

            # One best-effort reload mid-way to coax the SPA into firing requests.
            if not reloaded and (time.time() - start) > max(1.0, timeout_s / 3):
                reloaded = True
                try:
                    page.reload(wait_until="networkidle")
                except Exception:
                    pass

            time.sleep(0.2)
    finally:
        try:
            context.off("request", _on_request)
        except Exception:
            pass

    return auth_header["value"]


def fetch_my_accounts(context, auth_header: str) -> dict:
    url = "https://api.sparkasse.at/rest/netbanking/my/accounts"
    try:
        resp = context.request.get(url, headers={"Authorization": auth_header}, timeout=30000)
    except Exception as e:
        raise RuntimeError(f"[accounts] API request failed: {e}") from e

    if not resp or not resp.ok:
        status = resp.status if resp else "N/A"
        raise RuntimeError(f"[accounts] API request failed (status={status})")

    return resp.json()


def _extract_first(d: dict, keys: list[str]) -> object | None:
    for k in keys:
        if k in d and d.get(k) is not None:
            return d.get(k)
    return None


def _extract_amount(value) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        s = value.strip().replace(".", "").replace(",", ".")
        try:
            return float(s)
        except Exception:
            return None
    if isinstance(value, dict):
        # Common George money object: { value: 18245, precision: 2, currency: 'EUR' }
        if "value" in value and isinstance(value.get("value"), (int, float)):
            prec = value.get("precision")
            if isinstance(prec, int) and prec >= 0:
                return float(value.get("value")) / (10 ** prec)

        for k in ("value", "amount", "balance", "disposable", "available"):
            if k in value:
                out = _extract_amount(value.get(k))
                if out is not None:
                    return out
        for k in ("valueInCents", "amountInCents", "cents", "amountCents", "valueCents"):
            if k in value and isinstance(value.get(k), (int, float)):
                return float(value.get(k)) / 100.0
    return None


def _extract_currency(value) -> str | None:
    if isinstance(value, dict):
        for k in ("currency", "ccy"):
            v = value.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return None


def normalize_accounts_from_api(payload) -> list[dict]:
    if payload is None:
        return []

    accounts = None
    if isinstance(payload, list):
        accounts = payload
    elif isinstance(payload, dict):
        for key in ("items", "accounts", "data", "content", "accountList"):
            v = payload.get(key)
            if isinstance(v, list):
                accounts = v
                break
        else:
            accounts = [payload]
    else:
        return []

    normalized: list[dict] = []
    for acc in accounts:
        if not isinstance(acc, dict):
            continue
        acc_id = _extract_first(acc, ["id", "accountId", "uid", "uuid"])
        acc_type = _extract_first(acc, ["type", "accountType", "productType", "accountCategory"])
        name = _extract_first(acc, ["name", "alias", "productName", "description", "accountLabel", "accountName"])
        iban = _extract_first(acc, ["iban", "ibanNumber", "ibanFormatted"])
        currency = _extract_first(acc, ["currency", "ccy"])

        # George /my/accounts shape nests IBAN in accountno.iban
        if iban is None:
            accountno = acc.get("accountno") or acc.get("accountNo") or acc.get("accountNumber")
            if isinstance(accountno, dict):
                iban = accountno.get("iban") or accountno.get("IBAN")

        if isinstance(iban, dict):
            iban = _extract_first(iban, ["iban", "ibanNumber", "value"])

        entry = {
            "id": str(acc_id) if acc_id is not None else "",
            "type": (str(acc_type) if acc_type is not None else "").lower(),
            "name": str(name) if name is not None else "",
            "iban": str(iban) if iban is not None else None,
        }

        if currency:
            entry["currency"] = str(currency)

        desc = _extract_first(acc, ["description"])
        alias = _extract_first(acc, ["alias"])
        if desc:
            entry["description"] = str(desc)
        if alias:
            entry["alias"] = str(alias)

        normalized.append(entry)

    return normalized


def _extract_money_from_account(acc: dict, value_keys: list[str], currency_keys: list[str]) -> tuple[float | None, str | None]:
    raw = _extract_first(acc, value_keys)
    amount = _extract_amount(raw)
    currency = _extract_currency(raw) or _extract_first(acc, currency_keys)
    if isinstance(currency, str):
        currency = currency.strip()
    return amount, currency


def try_extract_iban_from_account_page(page, acc_type: str, acc_id: str) -> str | None:
    """Try to extract IBAN by visiting the account detail page.

    This is slower than scraping the overview but tends to be more reliable.
    """
    try:
        page.goto("about:blank")
        page.goto(f"{BASE_URL}/index.html#/{acc_type}/{acc_id}", wait_until="domcontentloaded", timeout=15000)
        # Give SPA some time to render details.
        time.sleep(2)
        dismiss_modals(page)
        body = page.inner_text("body")
        return _first_iban_in_text(body)
    except Exception:
        return None


def list_accounts_from_page(page) -> list[dict]:
    """Fetch account list from George dashboard."""
    print("[accounts] Fetching accounts from dashboard...", flush=True)
    # Avoid networkidle (SPA + long-polling). domcontentloaded is more reliable here.
    page.goto(DASHBOARD_URL, wait_until="domcontentloaded")
    ensure_list_layout(page)

    # Wait for account list + lazy loading
    try:
        page.wait_for_selector(".g-card-overview-title", timeout=30000)
        time.sleep(3)
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        time.sleep(3)
    except Exception:
        pass

    dismiss_modals(page)

    accounts = []

    # Parse account links from the overview (including loans)
    links = page.query_selector_all('a[href*="/currentAccount/"], a[href*="/saving/"], a[href*="/loan/"], a[href*="/credit/"], a[href*="/kredit/"], a[href*="/creditcard/"]')

    for link in links:
        try:
            href = link.get_attribute('href') or ""

            match = re.search(r'/(currentAccount|saving|loan|credit|kredit|creditcard)/([A-F0-9-]+)', href)
            if not match:
                continue

            acc_type = match.group(1)
            acc_id = match.group(2)

            # The IBAN is usually NOT inside the <a> text; it's nearby within the card.
            # Grab a larger text blob by walking up the DOM.
            card_text = ""
            try:
                card_text = link.evaluate(
                    """
                    (el) => {
                      let cur = el;
                      for (let i = 0; i < 10 && cur; i++) {
                        const t = (cur.innerText || '').trim();
                        if (t && t.length > 20) return t;
                        cur = cur.parentElement;
                      }
                      return (el.parentElement?.innerText || '').trim();
                    }
                    """
                )
            except Exception:
                card_text = (link.inner_text() or "")

            # Name: first line of the card text
            name = (card_text.split("\n")[0] if card_text else "").strip() or (link.inner_text() or "").split("\n")[0].strip()

            # IBAN: matches both spaced and non-spaced formats
            iban = _first_iban_in_text(card_text)

            accounts.append({
                "name": name,
                "iban": iban,
                "id": acc_id,
                "type": acc_type,
            })
        except Exception:
            continue

    # Deduplicate by ID
    seen = set()
    unique = []
    for acc in accounts:
        if acc["id"] not in seen:
            seen.add(acc["id"])
            unique.append(acc)

    return unique


def ensure_list_layout(page) -> None:
    """Ensure the dashboard is in list layout (not tiles).

    List layout is more consistent for scraping (IBAN next to available amount).
    """
    try:
        btn = page.locator('[data-cy="dashboard-view-mode-toggle-list-button"]')
        if btn.count() > 0:
            # If aria-pressed isn't true, click it.
            pressed = (btn.first.get_attribute("aria-pressed") or "").lower() == "true"
            if not pressed:
                btn.first.click(force=True)
                time.sleep(1)
    except Exception:
        pass


def list_account_balances_from_overview(page) -> list[dict]:
    """Return accounts with (balance, available) as shown on the George overview page."""
    # Avoid networkidle (SPA + long-polling). domcontentloaded is more reliable here.
    page.goto(DASHBOARD_URL, wait_until="domcontentloaded")
    ensure_list_layout(page)
    
    # Wait for skeletons to load
    print("[accounts] Waiting for account list to load...", flush=True)
    try:
        # Wait for at least one account title to appear
        page.wait_for_selector(".g-card-overview-title", timeout=30000)
        # Give it a bit more time for all to settle
        time.sleep(5)

        # Scroll to bottom to trigger lazy loading
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        print("[accounts] Scrolled to bottom, waiting 5s...", flush=True)
        time.sleep(5)

        # Try again after scroll (sometimes overview populates late)
        page.wait_for_selector(".g-card-overview-title", timeout=20000)
    except Exception:
        print("[accounts] Warning: Timeout waiting for account list", flush=True)

    dismiss_modals(page)
    
    # Account cards typically have a heading (h3) with account name and nearby balance text.
    # Include currentAccount, saving, loan/credit accounts, and credit cards
    cards = page.query_selector_all('h3:has(a[href*="/currentAccount/"]), h3:has(a[href*="/saving/"]), h3:has(a[href*="/loan/"]), h3:has(a[href*="/credit/"]), h3:has(a[href*="/kredit/"]), h3:has(a[href*="/creditcard/"])')

    results: list[dict] = []

    def parse_amount(s: str) -> float:
        return float(s.replace('.', '').replace(',', '.'))

    for h3 in cards:
        try:
            name = (h3.inner_text() or "").strip()
            link = h3.query_selector('a')
            href = link.get_attribute('href') if link else ""
            m = re.search(r'/(currentAccount|saving|loan|credit|kredit|creditcard)/([A-F0-9-]+)', href or "")
            if not m:
                continue
            acc_type, acc_id = m.group(1), m.group(2)
            
            # Debug: print card info
            # print(f"[debug] Checking card: {name} ({acc_type}/{acc_id})", flush=True)

            # Grab surrounding card text: climb ancestors until we see currency/amount patterns
            card_text = ""
            try:
                card_text = h3.evaluate(
                    """
                    (el) => {
                      const want = /(amount|betrag|stand|eur|usd|chf|gbp|€|minus|[0-9]{1,3}(\\.[0-9]{3})*,[0-9]{2})/i;
                      let cur = el;
                      for (let i = 0; i < 10 && cur; i++) {
                        const t = (cur.innerText || '').trim();
                        if (t && t.length > 20 && want.test(t)) {
                          return t;
                        }
                        cur = cur.parentElement;
                      }
                      // fallback: parent text
                      return (el.parentElement?.innerText || '').trim();
                    }
                    """
                )
            except Exception:
                card_text = (h3.inner_text() or "").strip()
            
            # Debug: print card info if needed
            # print(f"[debug] Card: {name} | Text: {card_text!r}", flush=True)

            # BALANCE: prefer the "Amount:" line if present
            balance = None
            currency = None

            # Accept currency codes or symbols
            ccy_pat = r'(EUR|USD|CHF|GBP|€|\$)'

            # Matches e.g. "Amount: 852,53 EUR" or German variants
            # Note: The "Amount:" line often has raw numbers like 155470,53 (no dots),
            # while the UI display has 155.470,53. We match both.
            amount_match = re.search(
                rf'(Amount|Betrag|Stand)\s*:?\s*(Minus\s+)?([0-9.]+,\s*[0-9]{{2}})\s*{ccy_pat}',
                card_text,
                re.IGNORECASE,
            )
            if amount_match:
                sign = -1 if amount_match.group(2) else 1
                balance = sign * parse_amount(amount_match.group(3))
                currency = amount_match.group(4)
            else:
                # Fallback: first currency amount on the card
                any_match = re.search(rf'(Minus\s+)?([0-9.]+,\s*[0-9]{{2}})\s*{ccy_pat}', card_text)
                if any_match:
                    sign = -1 if any_match.group(1) else 1
                    balance = sign * parse_amount(any_match.group(2))
                    currency = any_match.group(3)

            # Normalize currency symbols
            if currency == '€':
                currency = 'EUR'
            if currency == '$':
                currency = 'USD'

            # AVAILABLE: e.g. "434,65 EUR available" or "€ 434,65 available" or "verfügbar"
            available = None
            available_currency = None
            # Try pattern: "amount CCY available" or "CCY amount available"
            avail_match = re.search(
                rf'([0-9]{{1,3}}(?:\.[0-9]{{3}})*,[0-9]{{2}})\s*{ccy_pat}\s*(available|verf\u00fcgbar)',
                card_text,
                re.IGNORECASE,
            )
            if not avail_match:
                # Try: "€ 434,65 available"
                avail_match = re.search(
                    rf'{ccy_pat}\s*([0-9]{{1,3}}(?:\.[0-9]{{3}})*,[0-9]{{2}})\s*(available|verf\u00fcgbar)',
                    card_text,
                    re.IGNORECASE,
                )
            if avail_match:
                # Groups depend on which pattern matched
                g1, g2 = avail_match.group(1), avail_match.group(2)
                # Figure out which is amount vs currency
                if re.match(r'[0-9]', g1):
                    available = parse_amount(g1)
                    available_currency = g2
                else:
                    available_currency = g1
                    available = parse_amount(g2)
                if available_currency == '€':
                    available_currency = 'EUR'
                if available_currency == '$':
                    available_currency = 'USD'
            else:
                # Debug if the card mentions available/verfügbar but regex didn't match
                if re.search(r'(available|verf)', card_text, re.IGNORECASE):
                    snippet = re.sub(r'\s+', ' ', card_text).strip()[:220]
                    print(f"[balances] WARN could not parse AVAILABLE for '{name}'. Snippet: {snippet}", flush=True)

            # Debug snippet if we failed to parse
            if balance is None:
                snippet = re.sub(r'\s+', ' ', card_text).strip()[:180]
                print(f"[balances] WARN could not parse balance for '{name}'. Snippet: {snippet}", flush=True)

            results.append({
                "name": name,
                "type": acc_type,
                "id": acc_id,
                "balance": balance,
                "currency": currency,
                "available": available,
                "available_currency": available_currency,
            })
        except Exception:
            continue

    # Deduplicate by id
    seen = set()
    out = []
    for r in results:
        if r["id"] in seen:
            continue
        seen.add(r["id"])
        out.append(r)
    return out


def download_statements_pdf(page, account: dict, statement_ids: list[int], 
                            include_receipts: bool = True, download_dir: Path = None) -> list[Path]:
    """Download PDF statements for an account."""
    acc_type = account["type"]
    acc_id = account["id"]
    acc_name = account["name"]
    
    url = f"https://george.sparkasse.at/index.html#/{acc_type}/{acc_id}/statements"
    print(f"[statements] Downloading statements {statement_ids} for {acc_name}...", flush=True)
    
    page.goto(url, wait_until="networkidle")
    time.sleep(2)
    dismiss_modals(page)
    time.sleep(1)
    
    # Enter multi-select mode
    try:
        page.get_by_role("button", name="Download multiple").click()
        time.sleep(1)
    except Exception:
        print("[statements] Could not find 'Download multiple' button", flush=True)
        return []
    
    # Select statements
    for stmt_id in statement_ids:
        try:
            page.get_by_role("checkbox", name=f"Statement - {stmt_id}").check()
            time.sleep(0.3)
        except Exception:
            print(f"[statements] WARNING: Could not find statement {stmt_id}", flush=True)
    
    # Click Download
    print("[statements] Opening download dialog...", flush=True)
    try:
        page.get_by_role("button", name="Download").first.click()
    except Exception:
        btn = page.query_selector('button:has-text("Download"):not([disabled])')
        if btn:
            btn.click()
    time.sleep(2)
    
    # Check "incl. booking receipts"
    if include_receipts:
        print("[statements] Checking 'incl. booking receipts'...", flush=True)
        try:
            page.get_by_text("booking receipts").click()
            time.sleep(0.5)
        except Exception as e:
            print(f"[statements] Could not check receipts: {e}", flush=True)
    
    # Click Download in dialog
    print("[statements] Starting download...", flush=True)
    try:
        with page.expect_download(timeout=120000) as download_info:
            modal_download = page.locator('.g-modal button:has-text("Download")')
            if modal_download.count() > 0:
                modal_download.first.click(force=True)
            else:
                page.get_by_role("button", name="Download").last.click(force=True)
        
        download = download_info.value
        print(f"[statements] Downloaded: {download.suggested_filename}", flush=True)
        
        if download_dir:
            dest = download_dir / download.suggested_filename
            download.save_as(dest)
            print(f"[statements] Saved: {dest}", flush=True)
            return [dest]
    except Exception as e:
        print(f"[statements] Download failed: {e}", flush=True)
    
    return []


EXPORT_TYPES = ["camt53", "mt940"]
DEFAULT_EXPORT_TYPE = "camt53"
EXPORT_TYPE_LABELS = {
    "camt53": "CAMT53",
    "mt940": "MT940",
}

DATACARRIER_UPLOAD_URL = "https://george.sparkasse.at/index.html#/datacarrier/upload"
DATACARRIER_SIGN_URL_TEMPLATE = "https://george.sparkasse.at/index.html#/datacarrier/upload/sign/{datacarrier_id}?returnUrl=%2Fdatacarrier%2Fupload"
DATACARRIER_SIGN_API_TEMPLATE = "https://api.sparkasse.at/rest/netbanking/my/orders/datacarriers/{datacarrier_id}/sign/"
DATACARRIER_FILES_API_URL = "https://api.sparkasse.at/rest/netbanking/my/orders/datacarrier-files"


def download_data_exports(page, export_type: str, download_dir: Path = None) -> list[Path]:
    """Download data exports (CAMT53/MT940) for all available accounts."""
    export_type = export_type.lower()
    if export_type not in EXPORT_TYPES:
        print(f"[export] Invalid type '{export_type}'. Supported: {', '.join(EXPORT_TYPES)}", flush=True)
        return []

    label = EXPORT_TYPE_LABELS[export_type]
    print(f"[export] Downloading {label} data exports (all accounts)...", flush=True)

    page.goto("https://george.sparkasse.at/index.html#/datacarrier/download", wait_until="networkidle")
    time.sleep(2)
    dismiss_modals(page)

    downloaded = []
    rows = page.query_selector_all(f'tr:has-text("{label}")')
    if not rows:
        print(f"[export] No {label} exports found", flush=True)
        return []

    for row in rows:
        download_btn = row.query_selector("button")
        if not download_btn:
            continue
        try:
            with page.expect_download(timeout=30000) as download_info:
                download_btn.click()
            dl = download_info.value
            if download_dir:
                dest = download_dir / dl.suggested_filename
                dl.save_as(dest)
                print(f"[export] Saved: {dest.name}", flush=True)
                downloaded.append(dest)
            time.sleep(1)
        except Exception as e:
            print(f"[export] Download failed: {e}", flush=True)

    return downloaded


def _click_first_visible_button(page, selectors: list[str]) -> bool:
    for selector in selectors:
        try:
            btn = page.query_selector(selector)
            if btn and btn.is_visible():
                btn.click()
                return True
        except Exception:
            continue
    return False


def _try_select_datacarrier_type(page, file_type: str) -> None:
    if not file_type:
        return

    # Try native <select> first
    try:
        select_el = page.locator("select")
        if select_el.count() > 0:
            select_el.first.select_option(label=file_type)
            time.sleep(0.5)
            return
    except Exception:
        pass

    # Try combobox/option roles
    try:
        combo = page.get_by_role("combobox").first
        if combo and combo.is_visible():
            combo.click()
            time.sleep(0.3)
            option = page.get_by_role("option", name=re.compile(re.escape(file_type), re.I))
            if option.count() > 0:
                option.first.click()
                time.sleep(0.3)
                return
    except Exception:
        pass

    # Fallback: clickable labels/buttons with the type text
    try:
        btn = page.locator(f'button:has-text("{file_type}")')
        if btn.count() > 0 and btn.first.is_visible():
            btn.first.click()
            time.sleep(0.3)
            return
    except Exception:
        pass


def upload_datacarrier_file(page, file_path: Path, file_type: str | None = None) -> dict | None:
    print(f"[datacarrier-upload] Opening upload page...", flush=True)
    page.goto(DATACARRIER_UPLOAD_URL, wait_until="domcontentloaded")
    time.sleep(2)
    dismiss_modals(page)

    if file_type:
        print(f"[datacarrier-upload] Selecting type: {file_type}", flush=True)
        _try_select_datacarrier_type(page, file_type)

    def _is_datacarrier_response(resp) -> bool:
        try:
            return resp.request.method == "POST" and "/datacarrier-files" in (resp.url or "")
        except Exception:
            return False

    upload_buttons = [
        'button:has-text("Upload")',
        'button:has-text("Send")',
        'button:has-text("Submit")',
        'button:has-text("Import")',
        'button:has-text("Start")',
        'button:has-text("Weiter")',
        'button:has-text("Senden")',
        'button[type="submit"]',
    ]

    # Find the file input
    try:
        file_input = page.locator('input[type="file"]')
        file_input.wait_for(timeout=30000)
    except Exception as e:
        print(f"[datacarrier-upload] ERROR: Could not find file input: {e}", flush=True)
        return None

    response = None
    try:
        with page.expect_response(_is_datacarrier_response, timeout=120000) as resp_info:
            file_input.set_input_files(str(file_path))
            clicked = _click_first_visible_button(page, upload_buttons)
            if not clicked:
                # Some UIs auto-upload after file selection
                pass
        response = resp_info.value
    except PlaywrightTimeout:
        print("[datacarrier-upload] ERROR: Timed out waiting for upload response", flush=True)
        return None

    try:
        return response.json()
    except Exception:
        try:
            text = response.text()
            return {"raw": text}
        except Exception:
            return {"raw": "<unparseable response>"}


def _extract_sign_state(payload: dict | None) -> tuple[str | None, str | None]:
    if not isinstance(payload, dict):
        return None, None
    sign_id = payload.get("signId") or payload.get("id")
    sign_info = payload.get("signInfo")
    state = None
    if isinstance(sign_info, dict):
        state = sign_info.get("state")
    return sign_id, state


def _extract_sign_id_from_url(url: str | None) -> str | None:
    if not url:
        return None
    try:
        path = urlsplit(url).path or ""
        parts = [p for p in path.split("/") if p]
        if not parts:
            return None
        # .../datacarriers/<id>/sign/<signId>
        if parts[-1] and parts[-1].lower() != "sign":
            return parts[-1]
    except Exception:
        return None
    return None


def _build_datacarrier_files_list_url() -> str:
    return f"{DATACARRIER_FILES_API_URL}?page=0&size=100"


def _extract_datacarrier_file_state(payload, file_id: str | int | None) -> tuple[str | None, dict | None]:
    if file_id is None:
        return None, None

    items = []
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        for key in ("items", "data", "datacarrierFiles", "files", "content"):
            v = payload.get(key)
            if isinstance(v, list):
                items = v
                break
        else:
            items = [payload]

    file_id_s = str(file_id)
    for item in items:
        if not isinstance(item, dict):
            continue
        item_id = item.get("id") or item.get("fileId") or item.get("uuid")
        if item_id is not None and str(item_id) == file_id_s:
            state = item.get("state") or item.get("status")
            return state, item
    return None, None


def _click_confirmation_button(page) -> bool:
    try:
        locator = page.get_by_role("button", name=re.compile(r"(sign|confirm|weiter|best.?tigen)", re.I))
        count = locator.count()
        for idx in range(count):
            btn = locator.nth(idx)
            try:
                if btn.is_visible():
                    btn.click()
                    return True
            except Exception:
                continue
    except Exception:
        return False
    return False


def _parse_ddmmyyyy(s: str) -> date:
    return datetime.strptime(s, "%d.%m.%Y").date()


def _normalize_date_range(date_from: str | None, date_to: str | None) -> tuple[str | None, str]:
    """Return (date_from, date_to) as strings in DD.MM.YYYY.

    - date_to defaults to today
    - if date_to is in the future, clamp to today
    """
    today = date.today()

    df = _parse_ddmmyyyy(date_from) if date_from else None
    dt = _parse_ddmmyyyy(date_to) if date_to else today

    if dt > today:
        dt = today

    if df and df > dt:
        raise ValueError(f"date_from {df} is after date_to {dt}")

    df_s = df.strftime("%d.%m.%Y") if df else None
    dt_s = dt.strftime("%d.%m.%Y")
    return df_s, dt_s


# Supported transaction export formats
TRANSACTION_EXPORT_FORMATS = ["csv", "json", "ofx", "xlsx"]
DEFAULT_TRANSACTION_FORMAT = "csv"

# Map format names to George UI labels (case-insensitive matching used)
TRANSACTION_FORMAT_LABELS = {
    "csv": "CSV",
    "json": "JSON",
    "ofx": "OFX",
    "xlsx": "Excel",  # George may show "Excel" or "XLSX"
}

def download_transactions(page, account: dict, date_from: str = None, date_to: str = None,
                          download_dir: Path = None, fmt: str = "csv") -> list[Path]:
    """Download transactions for an account in the specified format.
    
    Args:
        page: Playwright page object
        account: Account dict with type, id, name, iban
        date_from: Start date (DD.MM.YYYY)
        date_to: End date (DD.MM.YYYY)
        download_dir: Directory to save downloaded file
        fmt: Export format (csv, json, ofx, xlsx)
    
    Returns:
        List of downloaded file paths
    """
    acc_type = account["type"]
    acc_id = account["id"]
    acc_name = account["name"]
    fmt = fmt.lower()
    
    if fmt not in TRANSACTION_EXPORT_FORMATS:
        print(f"[transactions] Invalid format '{fmt}'. Supported: {', '.join(TRANSACTION_EXPORT_FORMATS)}", flush=True)
        return []
    
    url = f"https://george.sparkasse.at/index.html#/{acc_type}/{acc_id}"
    print(f"[transactions] Downloading {fmt.upper()} transactions for {acc_name}...", flush=True)
    
    page.goto(url, wait_until="networkidle")
    time.sleep(2)
    dismiss_modals(page)
    
    # Look for export/download button in transaction history
    # George has a "Print Overview" or export option
    try:
        # Try to find export button
        export_btn = page.query_selector('button:has-text("Export")')
        if not export_btn:
            export_btn = page.query_selector('button:has-text("Download")')
        if not export_btn:
            # Look for three-dot menu
            more_btn = page.query_selector('button:has-text("More")')
            if more_btn:
                more_btn.click()
                time.sleep(1)
                export_btn = page.query_selector('button:has-text("Export")')
        
        if export_btn:
            export_btn.click()
            time.sleep(2)
            
            # Select the requested format
            format_label = TRANSACTION_FORMAT_LABELS.get(fmt, fmt.upper())
            format_option = page.query_selector(f'text={format_label}')
            if not format_option and fmt == "xlsx":
                # Try alternate labels for Excel
                format_option = page.query_selector('text=XLSX') or page.query_selector('text=Excel')
            if format_option:
                format_option.click()
                time.sleep(1)
            elif fmt != "csv":
                # If specific format not found and it's not CSV, warn user
                print(f"[transactions] Warning: Could not find {fmt.upper()} option, attempting default download", flush=True)
            
            # Click final download
            with page.expect_download(timeout=60000) as download_info:
                dl_btn = page.query_selector('button:has-text("Download")')
                if dl_btn:
                    dl_btn.click(force=True)
            
            dl = download_info.value
            if download_dir:
                # Normalize filename to include account + date range (and clamp future end-date to today)
                iban = (account.get("iban") or "").replace(" ", "")
                if not iban:
                    iban = account.get("id")

                df, dt = _normalize_date_range(date_from, date_to)
                df_iso = _parse_ddmmyyyy(df).isoformat() if df else f"{date.today().year}-01-01"
                dt_iso = _parse_ddmmyyyy(dt).isoformat()

                dest = download_dir / f"{iban}_{df_iso}_{dt_iso}.{fmt}"
                dl.save_as(dest)
                print(f"[transactions] Saved: {dest}", flush=True)
                return [dest]
        else:
            print("[transactions] Could not find export button - trying History page", flush=True)
            
            # Navigate to history page
            history_url = f"https://george.sparkasse.at/index.html#/{acc_type}/{acc_id}/history"
            page.goto(history_url, wait_until="networkidle")
            time.sleep(2)
            
            # TODO: Implement date filtering and export from history
            print("[transactions] History-based export not yet implemented", flush=True)
            
    except Exception as e:
        print(f"[transactions] Export failed: {e}", flush=True)
    
    return []


# Legacy alias for backward compatibility
def download_csv_transactions(page, account: dict, date_from: str = None, date_to: str = None,
                              download_dir: Path = None) -> list[Path]:
    """Download transaction CSV for an account. (Legacy - use download_transactions instead)"""
    return download_transactions(page, account, date_from, date_to, download_dir, fmt="csv")


# =============================================================================
# CLI Commands
# =============================================================================

def cmd_login(args):
    """Perform standalone login."""
    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=str(PROFILE_DIR),
            headless=not args.visible,
            viewport={"width": 1280, "height": 900},
        )
        page = context.new_page()
        try:
            if login(page, timeout_seconds=_login_timeout(args)):
                print("[login] Success! Session saved.", flush=True)
                return 0
            else:
                return 1
        finally:
            context.close()

def cmd_logout(args):
    """Clear session profile."""
    profile_dir = PROFILE_DIR
    if profile_dir.exists():
        import shutil
        try:
            shutil.rmtree(profile_dir)
            print(f"[logout] Removed profile at {profile_dir}", flush=True)
            return 0
        except Exception as e:
            print(f"[logout] Error removing profile: {e}", flush=True)
            return 1
    else:
        print("[logout] No session found.", flush=True)
        return 0


def _resolve_user_id(args, config: dict) -> str:
    """Resolve the George user_id.

    Precedence:
    1) --user-id
    2) GEORGE_USER_ID from environment (optionally via state-dir .env)
    3) config.json user_id (only if exactly one)

    If config has no user_id or more than one, raise with guidance.
    """
    if getattr(args, "user_id", None):
        return str(args.user_id).strip()

    env_uid = os.environ.get("GEORGE_USER_ID")
    if env_uid:
        return env_uid.strip()

    uid = config.get("user_id")
    if uid is None or uid == "":
        raise ValueError(
            "No user_id configured. Set one of:\n"
            "- pass --user-id <your-user-number-or-username>\n"
            "- set GEORGE_USER_ID (or put it in ~/.clawdbot/george/.env)\n"
            "- add user_id to config.json"
        )

    if isinstance(uid, str):
        return uid.strip()

    if isinstance(uid, list):
        uids = [str(x).strip() for x in uid if str(x).strip()]
        if len(uids) == 1:
            return uids[0]
        raise ValueError(
            "Multiple user_id entries found in config.json.\n"
            "Fix by keeping exactly one, or use --user-id / GEORGE_USER_ID to override."
        )

    raise ValueError("Invalid user_id in config.json")


def cmd_setup(args):
    """Setup George user ID and ensure playwright is installed."""

    print("[setup] George Banking Setup")
    print()
    
    # Get user ID
    if args.user_id:
        user_id = args.user_id
    else:
        print("Your George user ID can be found in the George app.")
        print("It can be an 8–9 digit Verfügernummer or a custom username.")
        print("Tip: you can also set GEORGE_USER_ID in ~/.clawdbot/george/.env")
        print()
        user_id = input("User ID: ").strip()
    
    if not user_id:
        print("[setup] ERROR: User ID required")
        return 1
    
    # Create config directory
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    DEFAULT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Create config.json
    config = {
        "user_id": user_id,
        "accounts": []
    }
    
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=4)

    print(f"[setup] ✓ Config saved to {CONFIG_PATH}")
    print(f"[setup] To discover accounts, run: george.py accounts")
    print(f"[setup] To override user_id without editing config: george.py --user-id <id> ...")
    
    # Check playwright
    print("[setup] Checking playwright...")
    try:
        from playwright.sync_api import sync_playwright
        print("[setup] ✓ Playwright already installed")
    except ImportError:
        print("[setup] Installing playwright...")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "playwright"], check=True)
            print("[setup] ✓ Playwright installed")
        except subprocess.CalledProcessError:
            print("[setup] ERROR: Failed to install playwright")
            print("[setup] Run manually: pip install playwright")
            return 1
    
    # Install chromium browser
    print("[setup] Installing chromium browser...")
    try:
        subprocess.run(["playwright", "install", "chromium"], check=True)
        print("[setup] ✓ Chromium installed")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[setup] WARNING: Could not install chromium")
        print("[setup] Run manually: playwright install chromium")
    
    print()
    print("[setup] ✓ Setup complete!")
    print(f"[setup] Next steps:")
    print(f"  1. george.py accounts                # Discover + save your accounts")
    print(f"  2. george.py balances           # Test with balances")
    
    return 0


def cmd_accounts(args):
    """List accounts (with balances/value) in a unified format."""
    global CONFIG
    if CONFIG is None:
        CONFIG = load_config()

    cached_accounts: list[dict] = CONFIG.get("accounts", []) or []

    do_fetch = not bool(getattr(args, "no_fetch", False))
    if bool(getattr(args, "fetch", False)):
        do_fetch = True

    raw_payload = None
    raw_path = None
    normalized: list[dict] = []

    if do_fetch:
        print("[accounts] Fetching live accounts via George API...", flush=True)
        with sync_playwright() as p:
            context = p.chromium.launch_persistent_context(
                user_data_dir=str(PROFILE_DIR),
                headless=not args.visible,
                viewport={"width": 1280, "height": 900},
            )
            page = context.new_page()

            try:
                if not login(page, timeout_seconds=_login_timeout(args)):
                    return 1

                dismiss_modals(page)

                # Try cached token first to avoid re-capturing headers.
                token_cache = _load_token_cache() or {}
                token = token_cache.get("accessToken") if isinstance(token_cache, dict) else None
                if isinstance(token, str) and token.strip():
                    try:
                        raw_payload = fetch_my_accounts(context, f"Bearer {token.strip()}")
                    except Exception:
                        raw_payload = None

                if raw_payload is None:
                    auth_header = capture_bearer_auth_header(context, page, timeout_s=10)
                    if not auth_header:
                        print("[accounts] ERROR: Could not capture API Authorization header", flush=True)
                        return 1

                    raw_payload = fetch_my_accounts(context, auth_header)
                    tok = _extract_bearer_token(auth_header)
                    if tok:
                        _save_token_cache(tok, source="auth_header")

                raw_path = _write_debug_json("my-accounts-raw", raw_payload)

                normalized = normalize_accounts_from_api(raw_payload)

                # Persist identity-only account list in config (stable mapping for later commands)
                CONFIG["accounts"] = normalized
                save_config(CONFIG)

            finally:
                context.close()

    else:
        normalized = cached_accounts

    if not normalized:
        if getattr(args, "json", False):
            print(json.dumps({"institution": "george", "fetchedAt": _now_iso_local(), "rawPath": None, "accounts": []}, indent=2))
        else:
            print("[accounts] No accounts found", flush=True)
        return 0

    wrapper = canonicalize_accounts_george(raw_payload, normalized, raw_path=raw_path)

    if getattr(args, "json", False):
        print(json.dumps(wrapper, ensure_ascii=False, indent=2))
        return 0

    print(f"[accounts] {len(wrapper['accounts'])} account(s):", flush=True)
    for acc in wrapper["accounts"]:
        name = acc.get("name") or "N/A"
        iban_short = _short_iban(acc.get("iban"))
        typ = acc.get("type") or "other"

        balances = acc.get("balances") if isinstance(acc.get("balances"), dict) else {}
        booked = balances.get("booked") if isinstance(balances, dict) else None
        available = balances.get("available") if isinstance(balances, dict) else None

        booked_s = "N/A"
        avail_s = None
        cur = acc.get("currency") or "EUR"
        if isinstance(booked, dict) and booked.get("amount") is not None:
            booked_s = f"{_eu_amount(float(booked['amount']))} {cur}"
        if isinstance(available, dict) and available.get("amount") is not None:
            avail_s = f"{_eu_amount(float(available['amount']))} {cur}"

        if avail_s and avail_s != booked_s:
            print(f"- {name} — {iban_short} — {booked_s} (avail {avail_s}) — {typ}", flush=True)
        else:
            print(f"- {name} — {iban_short} — {booked_s} — {typ}", flush=True)

    if wrapper.get("rawPath"):
        print(f"[accounts] raw payload saved: {wrapper['rawPath']}", flush=True)

    return 0



def cmd_balances(args):
    """List all accounts and their balances from the George overview."""
    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=str(PROFILE_DIR),
            headless=not args.visible,
            viewport={"width": 1280, "height": 900},
        )
        page = context.new_page()

        try:
            if not login(page, timeout_seconds=_login_timeout(args)):
                return 1

            dismiss_modals(page)
            auth_header = capture_bearer_auth_header(context, page, timeout_s=10)
            if not auth_header:
                print("[balances] ERROR: Could not capture API Authorization header", flush=True)
                return 1

            payload = fetch_my_accounts(context, auth_header)
            accounts = normalize_accounts_from_api(payload)

            def fmt(amount: float | None, cur: str | None) -> str:
                if amount is None:
                    return "N/A"
                cur = (cur or "EUR").strip()
                s = f"{amount:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
                return f"{s} {cur}"

            # Try to enrich with balance/disposable fields from raw payload if present.
            # We iterate over raw accounts to preserve any balance data.
            raw_accounts = None
            if isinstance(payload, list):
                raw_accounts = payload
            elif isinstance(payload, dict):
                for key in ("items", "accounts", "data", "content", "accountList"):
                    v = payload.get(key)
                    if isinstance(v, list):
                        raw_accounts = v
                        break
            if raw_accounts is None:
                raw_accounts = []

            print("[balances] Balances (API):", flush=True)
            for idx, acc in enumerate(raw_accounts):
                if not isinstance(acc, dict):
                    continue
                name = _extract_first(acc, ["name", "alias", "productName", "description", "accountLabel", "accountName"]) or "N/A"

                balance, currency = _extract_money_from_account(
                    acc,
                    ["balance", "accountBalance", "amount", "currentBalance", "value"],
                    ["currency", "ccy"],
                )
                disposable, disp_currency = _extract_money_from_account(
                    acc,
                    ["disposable", "disposableAmount", "available", "availableAmount", "disposableBalance"],
                    ["currency", "ccy"],
                )
                if disp_currency is None:
                    disp_currency = currency

                bal_str = fmt(balance, currency)
                disp_str = fmt(disposable, disp_currency)
                print(f"- {name}: {bal_str} (disposable: {disp_str})", flush=True)

            return 0
        finally:
            context.close()


def cmd_statements(args):
    """Download PDF statements for an account."""
    account = get_account(args.account)
    output_dir = Path(args.output) if args.output else DEFAULT_OUTPUT_DIR / f"{args.year}-Q{args.quarter}"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Statement IDs for Q4 (validated mapping)
    if args.quarter == 4:
        stmt_ids = [11, 12, 13, 14]
    else:
        raise NotImplementedError(f"Q{args.quarter} statement mapping not yet validated")
    
    print(f"[george] Downloading Q{args.quarter}/{args.year} statements for {account['name']}")
    
    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=str(PROFILE_DIR),
            headless=not args.visible,
            accept_downloads=True,
            downloads_path=str(output_dir),
            viewport={"width": 1280, "height": 900},
        )
        context.on("dialog", lambda d: d.accept())
        page = context.new_page()
        
        try:
            if not login(page, timeout_seconds=_login_timeout(args)):
                return 1
            
            dismiss_modals(page)
            files = download_statements_pdf(
                page, account, stmt_ids,
                include_receipts=not args.no_receipts,
                download_dir=output_dir
            )
            
            print(f"\n[george] Downloaded {len(files)} PDF files")
        finally:
            context.close()
    
    return 0


def cmd_export(args):
    """Download data exports (CAMT53/MT940) for all available accounts."""
    output_dir = Path(args.output) if args.output else DEFAULT_OUTPUT_DIR / "exports"
    output_dir.mkdir(parents=True, exist_ok=True)

    export_type = args.type.lower()
    if export_type not in EXPORT_TYPES:
        print(f"[export] Invalid type '{export_type}'. Supported: {', '.join(EXPORT_TYPES)}")
        return 1

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=str(PROFILE_DIR),
            headless=not args.visible,
            accept_downloads=True,
            downloads_path=str(output_dir),
            viewport={"width": 1280, "height": 900},
        )
        context.on("dialog", lambda d: d.accept())
        page = context.new_page()

        try:
            if not login(page, timeout_seconds=_login_timeout(args)):
                return 1

            dismiss_modals(page)
            files = download_data_exports(page, export_type, download_dir=output_dir)
            label = EXPORT_TYPE_LABELS[export_type]
            print(f"\n[george] Downloaded {len(files)} {label} export files")
        finally:
            context.close()

    return 0


def cmd_datacarrier_upload(args):
    """Upload a data-carrier file."""
    file_path = Path(args.file).expanduser()
    if not file_path.exists() or not file_path.is_file():
        print(f"[datacarrier-upload] ERROR: File not found: {file_path}", flush=True)
        return 1

    output_dir = Path(args.output) if args.output else None
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=str(PROFILE_DIR),
            headless=not args.visible,
            viewport={"width": 1280, "height": 900},
        )
        context.on("dialog", lambda d: d.accept())
        page = context.new_page()

        try:
            if not login(page, timeout_seconds=_login_timeout(args)):
                return 1

            dismiss_modals(page)
            payload = upload_datacarrier_file(page, file_path, args.type)
            if payload is None:
                return 1

            resp_id = None
            resp_status = None
            if isinstance(payload, dict):
                resp_id = (
                    payload.get("id")
                    or payload.get("fileId")
                    or payload.get("uuid")
                    or payload.get("reference")
                    or payload.get("datacarrierFileId")
                )
                resp_status = payload.get("status") or payload.get("state") or payload.get("result")

            id_part = f" id={resp_id}" if resp_id is not None else ""
            status_part = f" status={resp_status}" if resp_status is not None else ""
            print(f"[datacarrier-upload] Uploaded {file_path.name}{id_part}{status_part}", flush=True)

            if output_dir:
                ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                out_path = output_dir / f"{file_path.name}.datacarrier.{ts}.json"
                with open(out_path, "w") as f:
                    json.dump(payload, f, indent=2, sort_keys=True)
                print(f"[datacarrier-upload] Saved response: {out_path}", flush=True)

            if args.wait_done:
                if resp_id is None:
                    print("[datacarrier-upload] --wait-done requested but upload response has no file id", flush=True)
                else:
                    print(f"[datacarrier-upload] Waiting for file id={resp_id} to reach DONE...", flush=True)
                    last_state = None
                    start = time.time()
                    timeout_s = max(int(getattr(args, "wait_done_timeout", 120) or 0), 0)
                    while True:
                        if timeout_s > 0 and time.time() - start > timeout_s:
                            print(f"[datacarrier-upload] Timed out after {timeout_s}s waiting for DONE", flush=True)
                            break
                        try:
                            resp = context.request.get(_build_datacarrier_files_list_url(), timeout=30000)
                            payload = resp.json()
                        except Exception as e:
                            print(f"[datacarrier-upload] Polling error: {e}", flush=True)
                            time.sleep(3)
                            continue

                        state, _item = _extract_datacarrier_file_state(payload, resp_id)
                        if state and state != last_state:
                            print(f"[datacarrier-upload] State={state}", flush=True)
                            last_state = state
                        if state == "DONE":
                            break
                        time.sleep(3)
        finally:
            context.close()

    return 0


def cmd_datacarrier_sign(args):
    """Sign a data-carrier upload."""
    datacarrier_id = args.datacarrier_id
    output_dir = Path(args.output) if args.output else None
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=str(PROFILE_DIR),
            headless=not args.visible,
            viewport={"width": 1280, "height": 900},
        )
        context.on("dialog", lambda d: d.accept())
        page = context.new_page()

        try:
            if not login(page, timeout_seconds=_login_timeout(args)):
                return 1

            dismiss_modals(page)
            sign_page_url = DATACARRIER_SIGN_URL_TEMPLATE.format(datacarrier_id=datacarrier_id)
            sign_api_path = f"/rest/netbanking/my/orders/datacarriers/{datacarrier_id}/sign/"
            sign_api_base = DATACARRIER_SIGN_API_TEMPLATE.format(datacarrier_id=datacarrier_id)

            # Fast-path: if caller already knows the signId (from DevTools), we can skip UI network discovery.
            if getattr(args, "sign_id", None):
                sign_id = str(getattr(args, "sign_id")).strip()
                sign_api_url = f"{sign_api_base}{sign_id}"

                try:
                    post_response = context.request.post(
                        sign_api_url,
                        data=json.dumps({"authorizationType": "GEORGE_TOKEN"}),
                        headers={"Content-Type": "application/json"},
                        timeout=30000,
                    )
                except Exception as e:
                    print(f"[datacarrier-sign] ERROR: Signing request failed: {e}", flush=True)
                    return 1

                try:
                    post_payload = post_response.json() if post_response else None
                except Exception:
                    try:
                        post_payload = {"raw": post_response.text()} if post_response else None
                    except Exception:
                        post_payload = {"raw": "<unparseable response>"} if post_response else None

                auth_req_id = None
                poll_url = None
                poll_interval_ms = None
                if isinstance(post_payload, dict):
                    auth_req_id = post_payload.get("authorizationRequestId")
                    poll = post_payload.get("poll")
                    if isinstance(poll, dict):
                        poll_url = poll.get("url")
                        poll_interval_ms = poll.get("interval")

                _sid, state = _extract_sign_state(post_payload if isinstance(post_payload, dict) else None)
                state = state or (post_payload.get("state") if isinstance(post_payload, dict) else None)

                auth_part = f" authReqId={auth_req_id}" if auth_req_id else ""
                state_part = f" state={state}" if state else ""
                print(f"[datacarrier-sign] id={datacarrier_id} signId={sign_id}{state_part}{auth_part}", flush=True)

                if output_dir:
                    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                    out_path = output_dir / f"datacarrier-sign.{datacarrier_id}.{ts}.json"
                    with open(out_path, "w") as f:
                        json.dump(post_payload, f, indent=2, sort_keys=True)
                    print(f"[datacarrier-sign] Saved response: {out_path}", flush=True)

                # Optional: poll until the signing flow finishes (best-effort; shape may vary).
                if args.timeout and args.timeout > 0 and poll_url:
                    start = time.time()
                    last_state = state
                    interval_s = (poll_interval_ms / 1000.0) if isinstance(poll_interval_ms, (int, float)) and poll_interval_ms > 0 else float(max(args.poll, 1))
                    while time.time() - start < args.timeout:
                        try:
                            resp = context.request.get(poll_url, timeout=30000)
                            pj = resp.json()
                        except Exception:
                            time.sleep(interval_s)
                            continue

                        new_state = None
                        if isinstance(pj, dict):
                            new_state = (pj.get("state") or (pj.get("signInfo") or {}).get("state") or (pj.get("authorization") or {}).get("state"))
                        if new_state and new_state != last_state:
                            print(f"[datacarrier-sign] state={new_state}", flush=True)
                            last_state = new_state
                        if new_state and new_state not in ("OPEN", "PENDING", "PROCESSING"):
                            break
                        time.sleep(interval_s)

                return 0

            def _is_sign_any(resp) -> bool:
                try:
                    return sign_api_path in (resp.url or "") and resp.request.method in ("GET", "POST")
                except Exception:
                    return False

            def _is_sign_post(resp) -> bool:
                try:
                    return resp.request.method == "POST" and sign_api_path in (resp.url or "")
                except Exception:
                    return False

            initial_wait = args.timeout if args.timeout and args.timeout > 0 else 120
            response = None
            try:
                # Some George flows only load sign-info after interacting with the page.
                with page.expect_response(_is_sign_any, timeout=initial_wait * 1000) as resp_info:
                    page.goto(sign_page_url, wait_until="domcontentloaded")
                    time.sleep(2)
                    dismiss_modals(page)
                    # Best-effort: trigger any lazy-loaded sign-info.
                    _click_confirmation_button(page)
                response = resp_info.value
            except PlaywrightTimeout:
                print(
                    "[datacarrier-sign] ERROR: Timed out waiting for sign info (GET/POST). "
                    "Is the datacarrier id valid and in the right state?",
                    flush=True,
                )
                return 1

            try:
                payload = response.json() if response else None
            except Exception:
                try:
                    payload = {"raw": response.text()} if response else None
                except Exception:
                    payload = {"raw": "<unparseable response>"} if response else None

            sign_id, state = _extract_sign_state(payload if isinstance(payload, dict) else None)
            sign_id = sign_id or _extract_sign_id_from_url(response.url if response else None)
            sign_api_url = response.url if response and sign_id else f"{sign_api_base}{sign_id}" if sign_id else sign_api_base

            if output_dir:
                ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                out_path = output_dir / f"datacarrier-sign.{datacarrier_id}.{ts}.json"
                with open(out_path, "w") as f:
                    json.dump(payload, f, indent=2, sort_keys=True)
                print(f"[datacarrier-sign] Saved response: {out_path}", flush=True)

            # If the first observed response was already the POST, reuse it.
            post_response = response if (response and response.request.method == "POST") else None

            # If the POST happened in the background (e.g. triggered by our earlier click), catch it.
            if post_response is None:
                try:
                    post_response = page.wait_for_response(_is_sign_post, timeout=2000)
                except Exception:
                    post_response = None

            # Otherwise trigger it explicitly.
            if post_response is None:
                try:
                    with page.expect_response(_is_sign_post, timeout=10000) as resp_info:
                        _click_confirmation_button(page)
                    post_response = resp_info.value
                except PlaywrightTimeout:
                    post_response = None

            if post_response is None:
                try:
                    post_response = context.request.post(
                        sign_api_url,
                        data=json.dumps({"authorizationType": "GEORGE_TOKEN"}),
                        headers={"Content-Type": "application/json"},
                        timeout=30000,
                    )
                except Exception as e:
                    print(f"[datacarrier-sign] ERROR: Signing request failed: {e}", flush=True)
                    return 1

            try:
                post_payload = post_response.json() if post_response else None
            except Exception:
                try:
                    post_payload = {"raw": post_response.text()} if post_response else None
                except Exception:
                    post_payload = {"raw": "<unparseable response>"} if post_response else None

            auth_req_id = None
            if isinstance(post_payload, dict):
                auth_req_id = (
                    post_payload.get("authorizationRequestId")
                    or (post_payload.get("authorization") or {}).get("authorizationRequestId")
                    or (post_payload.get("authorizationRequest") or {}).get("id")
                )
            sign_id, state = _extract_sign_state(post_payload if isinstance(post_payload, dict) else None)
            sign_id = sign_id or _extract_sign_id_from_url(post_response.url if post_response else None)
            id_part = f" id={datacarrier_id}"
            sign_part = f" signId={sign_id}" if sign_id is not None else ""
            state_part = f" state={state}" if state is not None else ""
            auth_part = f" authReqId={auth_req_id}" if auth_req_id is not None else ""
            print(f"[datacarrier-sign]{id_part}{sign_part}{state_part}{auth_part}", flush=True)

            if args.timeout and args.timeout > 0:
                try:
                    thank_you = page.get_by_text("Thank you for signing.")
                    thank_you.wait_for(timeout=args.timeout * 1000)
                except Exception:
                    pass

                try:
                    ok_clicked = _click_first_visible_button(
                        page,
                        [
                            'button:has-text("OK")',
                            'button:has-text("Ok")',
                            'button:has-text("Okay")',
                        ],
                    )
                    if ok_clicked:
                        page.wait_for_url(re.compile(r".*#/datacarrier/dataCarrierList"), timeout=args.timeout * 1000)
                except Exception:
                    pass
        finally:
            context.close()

    return 0


def cmd_transactions(args):
    """Download transactions for an account in the specified format."""
    account = get_account(args.account)
    output_dir = Path(args.output) if args.output else DEFAULT_OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    
    fmt = args.format.lower()
    if fmt not in TRANSACTION_EXPORT_FORMATS:
        print(f"[transactions] Invalid format '{fmt}'. Supported: {', '.join(TRANSACTION_EXPORT_FORMATS)}")
        return 1

    # Normalize date range: --to defaults to today; future --to clamped to today
    try:
        date_from, date_to = _normalize_date_range(args.date_from, args.date_to)
    except Exception as e:
        print(f"[transactions] Invalid date range: {e}")
        return 1

    if args.date_to:
        # Informative log if user gave a future date
        try:
            if _parse_ddmmyyyy(args.date_to) > date.today():
                print(f"[transactions] NOTE: --to {args.date_to} is in the future; using today ({date_to}) instead", flush=True)
        except Exception:
            pass

    print(f"[george] Downloading {fmt.upper()} for {account['name']} ({date_from or 'DEFAULT'} -> {date_to})")

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=str(PROFILE_DIR),
            headless=not args.visible,
            accept_downloads=True,
            downloads_path=str(output_dir),
            viewport={"width": 1280, "height": 900},
        )
        context.on("dialog", lambda d: d.accept())
        page = context.new_page()

        try:
            if not login(page, timeout_seconds=_login_timeout(args)):
                return 1

            dismiss_modals(page)
            files = download_transactions(
                page, account,
                date_from=date_from,
                date_to=date_to,
                download_dir=output_dir,
                fmt=fmt,
            )

            print(f"\n[george] Downloaded {len(files)} {fmt.upper()} files")
        finally:
            context.close()

    return 0


def cmd_csv(args):
    """Download transaction CSV for an account. (Deprecated: use 'transactions' instead)"""
    print("[csv] Note: 'csv' command is deprecated. Use 'transactions -f csv' instead.", flush=True)
    # Create a fake args object with format=csv
    args.format = "csv"
    return cmd_transactions(args)


def main():
    parser = argparse.ArgumentParser(
        description="George Banking Automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  george.py setup                                # Initial setup (user ID + playwright)
  george.py accounts                             # If config has no accounts: fetch + save
  george.py statements -a main -y 2025 -q 4      # Download PDF statements
  george.py export                               # Download CAMT53 data exports (all accounts)
  george.py export --type mt940                  # Download MT940 data exports
  george.py transactions -a familie              # Download transactions (CSV default)
  george.py transactions -a familie -f json      # Download transactions as JSON
  george.py datacarrier-upload file.xml          # Upload data-carrier file
  george.py datacarrier-sign 123456              # Sign data-carrier upload
        """
    )
    
    # Global options
    parser.add_argument("--visible", action="store_true", help="Show browser window")
    parser.add_argument("--dir", default=None, help="State directory (default: ~/.clawdbot/george; override via GEORGE_DIR)")
    parser.add_argument("--login-timeout", type=int, default=DEFAULT_LOGIN_TIMEOUT, help="Seconds to wait for phone approval")
    parser.add_argument("--user-id", default=None, help="Override George user number/username (or set GEORGE_USER_ID)")
    
    subparsers = parser.add_subparsers(dest="command", required=True)

    # setup
    setup_parser = subparsers.add_parser("setup", help="Setup user ID and install playwright")
    setup_parser.add_argument("--user-id", help="George user ID (8-9 digit number)")
    setup_parser.set_defaults(func=cmd_setup)

    # login (standalone)
    login_parser = subparsers.add_parser("login", help="Perform login only")
    login_parser.set_defaults(func=cmd_login)

    # logout (standalone)
    logout_parser = subparsers.add_parser("logout", help="Clear session/profile")
    logout_parser.set_defaults(func=cmd_logout)

    # accounts
    acc_parser = subparsers.add_parser("accounts", help="List available accounts")
    acc_parser.add_argument("--fetch", action="store_true", help="Alias for default live fetch (updates config.json)")
    acc_parser.add_argument("--no-fetch", action="store_true", help="List cached config only (no API call)")
    acc_parser.add_argument("--json", action="store_true", help="Output canonical JSON")
    acc_parser.set_defaults(func=cmd_accounts)

    # balances
    bal_parser = subparsers.add_parser("balances", help="List all accounts with balances (API)")
    bal_parser.set_defaults(func=cmd_balances)

    # statements
    stmt_parser = subparsers.add_parser("statements", help="Download PDF statements")
    stmt_parser.add_argument("-a", "--account", required=True, help="Account key/name/IBAN")
    stmt_parser.add_argument("-y", "--year", type=int, required=True)
    stmt_parser.add_argument("-q", "--quarter", type=int, required=True, choices=[1, 2, 3, 4])
    stmt_parser.add_argument("-o", "--output", help="Output directory")
    stmt_parser.add_argument("--no-receipts", action="store_true", help="Skip booking receipts")
    stmt_parser.set_defaults(func=cmd_statements)
    
    # export (data export: CAMT53/MT940)
    export_parser = subparsers.add_parser(
        "export",
        help="Download data exports (CAMT53/MT940)",
        description=(
            "You can export (download) all available new data and files for all of your set-up accounts "
            "in order to use them for your bookkeeping. The Data Export is available as soon as the data "
            "for an account statement are available and a statement request with your selected frequency "
            "has been done. From then on, the Export will be available for a maximum of 3 months."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    export_parser.add_argument("--type", default=DEFAULT_EXPORT_TYPE, choices=EXPORT_TYPES,
                               help="Export type (default: camt53)")
    export_parser.add_argument("-o", "--output", help="Output directory")
    export_parser.set_defaults(func=cmd_export)

    # datacarrier-upload
    dc_upload_parser = subparsers.add_parser(
        "datacarrier-upload",
        help="Upload a data-carrier file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    dc_upload_parser.add_argument("file", help="Data-carrier file path to upload")
    dc_upload_parser.add_argument("--type", default="PACKAGE", help="Data-carrier type (default: PACKAGE)")
    dc_upload_parser.add_argument("-o", "--output", help="Output directory for response JSON")
    dc_upload_parser.add_argument("--wait-done", action="store_true", help="Poll until uploaded file state is DONE")
    dc_upload_parser.add_argument("--wait-done-timeout", type=int, default=120,
                                  help="Max seconds to wait for DONE (default: 120; 0 disables timeout)")
    dc_upload_parser.set_defaults(func=cmd_datacarrier_upload)

    # datacarrier-sign
    dc_sign_parser = subparsers.add_parser(
        "datacarrier-sign",
        help="Sign a data-carrier upload",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    dc_sign_parser.add_argument("datacarrier_id", help="Data-carrier upload id to sign")
    dc_sign_parser.add_argument("--sign-id", default=None, help="Optional signId (if you already captured it from the API/DevTools)")
    dc_sign_parser.add_argument("--timeout", type=int, default=120, help="Polling timeout in seconds (default: 120; 0 disables polling)")
    dc_sign_parser.add_argument("--poll", type=int, default=3, help="Polling interval in seconds (default: 3)")
    dc_sign_parser.add_argument("-o", "--output", help="Output directory for response JSON")
    dc_sign_parser.set_defaults(func=cmd_datacarrier_sign)

    # transactions (primary transaction export command)
    transactions_parser = subparsers.add_parser("transactions", help="Download transactions (csv/json/ofx/xlsx)")
    transactions_parser.add_argument("-a", "--account", required=True, help="Account key/name/IBAN")
    transactions_parser.add_argument("-f", "--format", default=DEFAULT_TRANSACTION_FORMAT,
                                     choices=TRANSACTION_EXPORT_FORMATS,
                                     help="Export format (default: csv)")
    transactions_parser.add_argument("-o", "--output", help="Output directory")
    transactions_parser.add_argument("--from", dest="date_from", help="Start date (DD.MM.YYYY)")
    transactions_parser.add_argument("--to", dest="date_to", help="End date (DD.MM.YYYY)")
    transactions_parser.set_defaults(func=cmd_transactions)
    
    # csv (deprecated alias for transactions -f csv)
    csv_parser = subparsers.add_parser("csv", help="[DEPRECATED] Use 'transactions' instead")
    csv_parser.add_argument("-a", "--account", required=True, help="Account key/name/IBAN")
    csv_parser.add_argument("-o", "--output", help="Output directory")
    csv_parser.add_argument("--from", dest="date_from", help="Start date (DD.MM.YYYY)")
    csv_parser.add_argument("--to", dest="date_to", help="End date (DD.MM.YYYY)")
    csv_parser.set_defaults(func=cmd_csv)
    
    args = parser.parse_args()
    _apply_state_dir(getattr(args, "dir", None))

    # Make --user-id available to login() without threading args everywhere.
    global USER_ID_OVERRIDE
    USER_ID_OVERRIDE = getattr(args, "user_id", None)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main() or 0)
