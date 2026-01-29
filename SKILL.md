---
name: george
description: "Automate George online banking (Erste Bank / Sparkasse Austria): login/logout, list accounts, and fetch transactions via Playwright."
summary: "George banking automation: login, accounts, transactions."
version: 1.1.0
homepage: https://github.com/odrobnik/george-skill
metadata: {"moltbot": {"emoji": "🏦", "requires": {"bins": ["python3", "playwright"]}}}
---

# George Banking Automation

Unified UX for George: **login**, **logout**, **accounts**, **transactions**.

**Entry point:** `{baseDir}/scripts/george.py`

## Commands

```bash
python3 {baseDir}/scripts/george.py login
python3 {baseDir}/scripts/george.py logout
python3 {baseDir}/scripts/george.py accounts
python3 {baseDir}/scripts/george.py transactions --account <id|iban> --from YYYY-MM-DD --until YYYY-MM-DD
```

## Notes
- Uses Playwright (phone approval during login).
- Session state stored in `~/.moltbot/george/` (override with `--dir`).
