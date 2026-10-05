# CLAUDE.md

Working rules for coding agents in this repository. Read `ARCHITECTURE.md` for
the layout and `METHOD.md` for the method and its limits.

## Commands

```bash
pip install -r requirements.txt && pip install -e ".[dev]"
cipherguard lab            # write the sample captures to samples/
cipherguard train          # train the ESP inference model into models/
ruff check .               # lint; must pass
ruff format .              # formatting; CI runs `ruff format --check`
python -m pytest tests/    # full suite, about 3 minutes
python -m pytest tests/ -m "not soak"
cipherguard serve          # dashboard on http://127.0.0.1:8000
cipherguard export-demo --out docs   # regenerate the static dashboard
```

## Rules that must not be broken

1. Never write code that decrypts ESP or IKE payloads, or that requests,
   reads or stores private keys, pre-shared keys or session keys.
2. Never persist packet payload bytes to disk, SQLite or logs. Store metadata
   only.
3. The RFC 4303 framing mask constrains the model output. Never let a model
   prediction override it, and never report an inference as a certainty.
4. Keep observed and inferred values separate in data models, exports and the
   interface.
5. No outbound network calls, analytics or CDN dependencies. The tool must work
   with no internet access.
6. `cipherguard serve` binds to loopback by default. A non-loopback bind
   requires `CIPHERGUARD_TOKEN`. Do not weaken that check.
7. Do not loosen the request checks in `cipherguard/api/security.py` (Host
   allowlist, cross-site refusal, content security policy, size limits). The
   page must not use inline scripts or inline event handlers.
8. Never show a stand-in value as if it were measured. If the server did not
   report something, the page shows an em dash or says it was not checked.

## Dependencies

- Prefer the standard library. Core dependencies are `numpy`, `scikit-learn`
  and `joblib`. `fastapi`, `uvicorn` and `pydantic` are for `serve` only.
- Do not add PyTorch, TensorFlow or Scapy.
- The dashboard is plain HTML, CSS and JavaScript. Do not add a CSS framework,
  a JavaScript framework or a build step.

## Dashboard changes

- Edit `cipherguard/api/static/`. `docs/` is the output of
  `cipherguard export-demo` and must not be edited by hand.
- The page runs in two modes: static, from precomputed JSON with no backend,
  and live, against the FastAPI server. A change must keep both working.
- Use the custom properties defined at the top of `css/dashboard.css`.
- The script is split into files under `js/` that share one global scope and
  load in the order listed in `index.html`. Put new code in the file for its
  area; `ARCHITECTURE.md` lists them.

## Conventions

- Type-annotate new Python functions.
- Explain non-obvious arithmetic in a comment (RFC 4303 padding, Mosca
  inequality). Keep existing docstrings.
- Do not let raw tracebacks reach CLI output. Report corrupt or truncated
  captures with the byte offset.
- Do not tell users to run the tool as root. Live capture needs `CAP_NET_RAW`
  only.
- Wi-Fi and VPN inspection must degrade to an empty result with a status
  message when no adapter is present, not raise.
- New features and dissector logic need tests in `tests/`. The suite must pass
  before a task is finished.
- Write plain commit messages that say what changed. Work on a branch and open
  a pull request instead of committing to `main`.
