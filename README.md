# George Skill

Unified web automation for George (Erste/Sparkasse): login, logout, accounts, transactions.

## Usage
```bash
python3 scripts/george.py login
python3 scripts/george.py logout
python3 scripts/george.py accounts
python3 scripts/george.py transactions --account <id|iban> --from YYYY-MM-DD --until YYYY-MM-DD
```

## Notes
- Playwright is required; login requires phone approval.
- Session state stored in `<workspace>/george/` by default (override with `--dir` / `GEORGE_DIR`).
- See `SKILL.md` for agent usage guidance.
