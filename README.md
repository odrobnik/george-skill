# George (Clawdbot Skill)

Banking automation for **George (Erste Bank / Sparkasse Austria)** using Playwright.

- **Main documentation:** `SKILL.md`
- **CLI entry point:** `scripts/george.py`

## Quick start

```bash
python3 scripts/george.py setup
python3 scripts/george.py accounts   # auto-fetches + stores accounts if empty
python3 scripts/george.py balances
```

State is stored outside the repo:
- `~/.clawdbot/george/config.json`
- `~/.clawdbot/george/.pw-profile/`
- `~/.clawdbot/george/data/`
