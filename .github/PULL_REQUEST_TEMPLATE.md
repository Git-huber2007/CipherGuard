## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## How it was checked

<!-- Commands you ran, captures you tested against, or a screenshot for dashboard changes. -->

## Checklist

- [ ] `pytest tests/` passes
- [ ] `ruff check .` passes
- [ ] New behaviour has a test
- [ ] Dashboard changes were made in `cipherguard/api/static/`, not `docs/`
- [ ] No decryption, no payload retention, no outbound network calls (see `ARCHITECTURE.md`, "Design rules")
