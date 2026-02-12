---
name: george
description: "Automate George online banking (Erste Bank / Sparkasse Austria): login/logout, list accounts, and fetch transactions via Playwright."
summary: "George banking automation: login, accounts, transactions."
version: 1.2.1
homepage: https://github.com/odrobnik/george-skill
metadata: {"openclaw": {"emoji": "🏦", "requires": {"bins": ["python3", "playwright"]}}}
---

# George Banking Automation

Fetch current account balances, stock portfolio, and transactions for all account types (checking, savings, depots) in JSON format for automatic processing. Uses Playwright to automate George (Erste Bank / Sparkasse Austria).

**Entry point:** `{baseDir}/scripts/george.py`

## Authentication

Requires **2FA via the George app** on your iPhone. When the script initiates login, a confirmation code is displayed. Open the George app and approve the login request if the code matches.

## Commands

```bash
python3 {baseDir}/scripts/george.py login
python3 {baseDir}/scripts/george.py logout
python3 {baseDir}/scripts/george.py accounts
python3 {baseDir}/scripts/george.py transactions --account <id|iban> --from YYYY-MM-DD --until YYYY-MM-DD
```

## Notes
- Session state stored in `{workspace}/george/` by default (override with `--dir` / `GEORGE_DIR`). The skill applies a strict umask and uses `chmod` to keep this state directory and the persisted `token.json` private (best-effort: dirs `700`, files `600`).
- Ephemeral exports default to `/tmp/openclaw/george` (override with `OPENCLAW_TMP`).
