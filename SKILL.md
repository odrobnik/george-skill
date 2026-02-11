---
name: george
description: "Automate George online banking (Erste Bank / Sparkasse Austria): login/logout, list accounts, and fetch transactions via Playwright."
summary: "George banking automation: login, accounts, transactions."
version: 1.1.1
homepage: https://github.com/odrobnik/george-skill
metadata: {"openclaw": {"emoji": "🏦", "requires": {"bins": ["python3", "playwright"]}}}
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
- Session state stored in `<workspace>/george/` by default (override with `--dir` / `GEORGE_DIR`). The skill applies a strict umask and uses `chmod` to keep this state directory and the persisted `token.json` private (best-effort: dirs `700`, files `600`).
- Ephemeral exports default to `/tmp/openclaw/george` (override with `OPENCLAW_TMP`, legacy `MOLTBOT_TMP`).
