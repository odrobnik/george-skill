---
name: george
description: Banking automation for George (Erste Bank/Sparkasse Austria) using Playwright. Use for login/session, listing accounts, balances, and downloading statements/transactions.
version: 1.0.0
metadata: {"clawdbot":{"requires":{"bins":["python3","playwright"]}}}
---

# George Banking Automation Skill

Modular automation for George (Erste Bank/Sparkasse Austria).

## Setup

**Quick setup (recommended):**
```bash
cd ./scripts
./george.py setup

# This will:
# - Prompt for your George user ID
# - Save config to ~/.clawdbot/george/config.json
# - Check/install playwright
# - Install chromium browser

# Then discover your accounts:
./george.py accounts --fetch
```

**Manual setup (alternative):**
```bash
# Install playwright
pipx install playwright
playwright install chromium

# Create config manually at ~/.clawdbot/george/config.json
mkdir -p ~/.clawdbot/george
cat > ~/.clawdbot/george/config.json <<EOF
{
    "user_id": "YOUR_USER_ID",
    "accounts": {}
}
EOF

# Discover accounts
./scripts/george.py accounts --fetch
```

## Commands

### Session Management

```bash
# Login (opens browser, waits for phone approval)
./scripts/george.py login

# Logout (clears session profile)
./scripts/george.py logout
```

*Note: Session is persisted in `~/.clawdbot/george/.pw-profile/` (or `--dir`).*

### List Accounts

```bash
# List accounts from config.json
./scripts/george.py accounts

# Fetch live from George (requires login)
./scripts/george.py accounts --fetch
```

### Check Balances

```bash
./scripts/george.py balances
```

### Download Data

**PDF Statements (quarterly, per account):**
```bash
./scripts/george.py statements -a main -y 2025 -q 4
```

**Data exports (for bookkeeping; all accounts):**
```bash
./scripts/george.py export              # CAMT53 (default)
./scripts/george.py export --type mt940
```

**Transactions (CSV/JSON/OFX/XLSX):**
```bash
# Default format (CSV) for today:
./scripts/george.py transactions -a main

# Specific formats:
./scripts/george.py transactions -a main -f json
./scripts/george.py transactions -a main -f ofx
./scripts/george.py transactions -a main -f xlsx

# With date range:
./scripts/george.py transactions -a main -f csv --from 01.01.2025 --to 31.01.2025
```

Supported formats: `csv` (default), `json`, `ofx`, `xlsx`

## Global Options

```
--visible          Show browser window (for debugging)
--dir DIR          State directory (default: ~/.clawdbot/george; override via GEORGE_DIR)
--login-timeout N  Seconds to wait for phone approval (default: 60)
```

## Output Locations

- **Data:** `~/.clawdbot/george/data/YYYY-QX/` (or `--dir`)
- **Config:** `~/.clawdbot/george/config.json` (or `--dir`)
- **Session:** `~/.clawdbot/george/.pw-profile/` (or `--dir`)
