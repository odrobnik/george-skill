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
from datetime import datetime, date
from pathlib import Path

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

DEFAULT_LOGIN_TIMEOUT = 60  # seconds


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

def _login_timeout(args) -> int:
    return getattr(args, "login_timeout", DEFAULT_LOGIN_TIMEOUT)

def load_config():
    """Load configuration from JSON file."""
    if not CONFIG_PATH.exists():
        print(f"ERROR: Config file not found at {CONFIG_PATH}")
        print("Please create it with your 'user_id' and 'accounts'.")
        sys.exit(1)
    
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

# Load configuration (lazy loaded later to allow help to run without config)
CONFIG = None


def get_account(account_key: str) -> dict:
    """Get account info by key, name fragment, or IBAN fragment."""
    global CONFIG
    if CONFIG is None:
        CONFIG = load_config()
        
    accounts = CONFIG.get("accounts", {})
    key = account_key.lower()
    
    # Direct key match
    if key in accounts:
        return accounts[key]
    
    # Search by name or IBAN fragment
    for k, acc in accounts.items():
        if key in acc["name"].lower():
            return acc
        if acc.get("iban") and key in acc["iban"].replace(" ", "").lower():
            return acc
    
    raise ValueError(f"Unknown account: {account_key}. Use 'accounts' command to list available accounts.")


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

        # Success: redirected to George dashboard
        if "george.sparkasse.at" in current_url and "login" not in current_url:
            print(f"\n[login] Approved! Redirected to: {current_url}", flush=True)
            return True

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
            print(f"[login] Still waiting... {remaining}s remaining", flush=True)

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
    
    # Try dashboard first to see if session is valid
    try:
        page.goto(DASHBOARD_URL, wait_until="networkidle", timeout=15000)
        time.sleep(2)
        if "login" not in page.url and "george.sparkasse.at" in page.url:
            print("[login] Session still valid!", flush=True)
            return True
    except Exception:
        pass

    print("[login] Session invalid/expired. Navigating to login page...", flush=True)
    page.goto(LOGIN_URL, wait_until="networkidle")
    page.wait_for_selector('input', timeout=10000)
    time.sleep(1)
    
    if "george.sparkasse.at" in page.url and "login" not in page.url:
        print("[login] Already logged in (redirected)!", flush=True)
        return True
    
    print(f"[login] Entering user ID...", flush=True)
    
    global CONFIG
    if CONFIG is None:
        CONFIG = load_config()
        
    user_id = CONFIG.get("user_id")
    if not user_id:
        print("[login] ERROR: 'user_id' not found in config.json")
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
    
    code = extract_verification_code(page)
    
    if code:
        print(f"[login] Verification code: {code}", flush=True)
    else:
        print("[login] ⚠️ Could not extract code - CHECK BROWSER WINDOW", flush=True)
    
    # NOTE: No macOS-specific notifications. Code is printed to stdout for the caller
    # (Clawdbot session) to forward via Telegram.
    return wait_for_login_approval(page, timeout_seconds=timeout_seconds)


def list_accounts_from_page(page) -> list[dict]:
    """Fetch account list from George dashboard."""
    print("[accounts] Fetching accounts from dashboard...", flush=True)
    page.goto(DASHBOARD_URL, wait_until="networkidle")
    
    # Wait for account list
    try:
        page.wait_for_selector(".g-card-overview-title", timeout=15000)
        time.sleep(5)
    except Exception:
        pass
        
    dismiss_modals(page)

    accounts = []

    # Parse account links from the overview (including loans)
    links = page.query_selector_all('a[href*="/currentAccount/"], a[href*="/saving/"], a[href*="/loan/"], a[href*="/credit/"], a[href*="/kredit/"]')

    for link in links:
        try:
            href = link.get_attribute('href') or ""
            text = link.inner_text() or ""

            match = re.search(r'/(currentAccount|saving|loan|credit|kredit)/([A-F0-9]+)', href)
            if not match:
                continue

            acc_type = match.group(1)
            acc_id = match.group(2)

            name = text.split('\n')[0].strip()

            iban = None
            iban_match = re.search(r'AT\d{2}\s*\d{4}\s*\d{4}\s*\d{4}\s*\d{4}', text)
            if iban_match:
                iban = iban_match.group(0)

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


def list_account_balances_from_overview(page) -> list[dict]:
    """Return accounts with (balance, available) as shown on the George overview page."""
    page.goto(DASHBOARD_URL, wait_until="networkidle")
    
    # Wait for skeletons to load
    print("[accounts] Waiting for account list to load...", flush=True)
    try:
        # Wait for at least one account title to appear
        page.wait_for_selector(".g-card-overview-title", timeout=15000)
        # Give it a bit more time for all to settle
        time.sleep(5)
        
        # Scroll to bottom to trigger lazy loading
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        print("[accounts] Scrolled to bottom, waiting 5s...", flush=True)
        time.sleep(5)
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


def cmd_setup(args):
    """Setup George user ID and ensure playwright is installed."""
    import getpass
    import subprocess
    
    print("[setup] George Banking Setup")
    print()
    
    # Get user ID
    if args.user_id:
        user_id = args.user_id
    else:
        print("Your George user ID can be found in the George app.")
        print("It's typically an 8-9 digit number.")
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
        "accounts": {}
    }
    
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=4)
    
    print(f"[setup] ✓ Config saved to {CONFIG_PATH}")
    print(f"[setup] To discover accounts, run: george.py accounts --fetch")
    
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
    print(f"  1. george.py accounts --fetch  # Discover your accounts")
    print(f"  2. george.py balances           # Test with balances")
    
    return 0


def cmd_accounts(args):
    """List available accounts."""
    global CONFIG
    if CONFIG is None:
        CONFIG = load_config()

    print("\n=== Known Accounts (from config) ===\n")
    accounts = CONFIG.get("accounts", {})
    for key, acc in accounts.items():
        iban = acc.get("iban") or "N/A"
        print(f"  {key:12} {acc['name']:25} {iban}")

    if args.fetch:
        with sync_playwright() as p:
            context = p.chromium.launch_persistent_context(
                user_data_dir=str(PROFILE_DIR),
                headless=not args.visible,
                viewport={"width": 1280, "height": 900},
            )
            page = context.new_page()

            try:
                if login(page, timeout_seconds=_login_timeout(args)):
                    dismiss_modals(page)
                    accounts = list_accounts_from_page(page)

                    print("\n=== Accounts from George ===\n")
                    for acc in accounts:
                        iban = acc.get("iban") or "N/A"
                        print(f"  {acc['type']:15} {acc['name']:25} {iban}")
                        print(f"    ID: {acc['id']}")
            finally:
                context.close()

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
            rows = list_account_balances_from_overview(page)

            # Print in a parseable format
            def fmt(amount: float | None, cur: str | None) -> str:
                if amount is None or not cur:
                    return "N/A"
                # 1234.56 -> 1.234,56
                s = f"{amount:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
                return f"{s} {cur}"

            print("\n=== Balances (George overview) ===\n")
            for r in rows:
                bal_str = fmt(r.get("balance"), r.get("currency"))
                avail_str = fmt(r.get("available"), r.get("available_currency") or r.get("currency"))
                if r.get("available") is not None:
                    print(f"- {r['name']}: {bal_str} (available: {avail_str})")
                else:
                    print(f"- {r['name']}: {bal_str}")

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
  george.py accounts --fetch                     # Fetch accounts from George
  george.py statements -a main -y 2025 -q 4      # Download PDF statements
  george.py export                               # Download CAMT53 data exports (all accounts)
  george.py export --type mt940                  # Download MT940 data exports
  george.py transactions -a familie              # Download transactions (CSV default)
  george.py transactions -a familie -f json      # Download transactions as JSON
        """
    )
    
    # Global options
    parser.add_argument("--visible", action="store_true", help="Show browser window")
    parser.add_argument("--dir", default=None, help="State directory (default: ~/.clawdbot/george; override via GEORGE_DIR)")
    parser.add_argument("--login-timeout", type=int, default=DEFAULT_LOGIN_TIMEOUT, help="Seconds to wait for phone approval")
    
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
    acc_parser.add_argument("--fetch", action="store_true", help="Fetch live from George (requires login)")
    acc_parser.set_defaults(func=cmd_accounts)

    # balances
    bal_parser = subparsers.add_parser("balances", help="List all accounts with balances (overview)")
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
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main() or 0)
