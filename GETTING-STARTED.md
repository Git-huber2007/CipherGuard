# Getting started

Five minutes from download to a running dashboard.

---

## Step 0 — What you need

- **Python 3.10 or newer** (`python3 --version`)
- Works on Linux, macOS and Windows. Live capture (`sensor`) is Linux-only;
  everything else runs anywhere.
- No Docker required. No root required, except for live capture.

---

## Step 1 — Get the code

```bash
git clone https://github.com/Git-huber2007/CipherGuard.git
cd CipherGuard
```

You should see `cipherguard/`, `samples/`, `models/`, `tests/`, `README.md`.

On Windows you can stop here and double-click `launch_dashboard.bat`: it
creates the virtual environment, installs the dependencies into it and opens
the dashboard. The steps below do the same by hand, on any platform.

---

## Step 2 — Install dependencies

A virtual environment keeps this off your system Python.

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.lock
pip install -e .
```

`requirements.lock` holds the exact versions the project is tested with. The
second install registers the `cipherguard` command; without it, write
`python -m cipherguard` wherever an example says `cipherguard`.

Takes about a minute. If `pip` complains on Debian or Ubuntu about an
externally-managed environment, you skipped the venv — go back and create it.

---

## Step 3 — The sample captures (already there)

`samples/` holds seven lab scenarios: a legacy IKEv1 gateway, a partially
modernised one, a hardened one, a mixed backbone, a downgrade capture, and two
post-quantum ones: an RFC 9370 hybrid key exchange, and the same offer declined
by the responder. Nothing needs generating.

To write them again:

```bash
python -m cipherguard lab
```

The nonces, SPIs and key-exchange values are random, so a regenerated capture
differs byte for byte from the committed one. What each scenario negotiates,
and so what the audit finds, is the same.

---

## Step 4 — The inference model (already there)

`models/` holds the trained model and the SHA-256 manifest it is checked
against before loading. To train it again:

```bash
python -m cipherguard train
```

About one minute. The seed is fixed, so with the pinned dependencies this
reproduces the committed model's figures: **100% framing-class** and
**60.6% exact-suite** accuracy on 360 held-out flows. The second number is low
because several ESP suites are byte-identical on the wire and cannot be told
apart by anything; [METHOD.md](METHOD.md#measured-accuracy-and-its-ceiling)
explains it.

---

## Step 5 — Run your first assessment

```bash
python -m cipherguard.cli analyze samples/backbone.pcap -v
```

You get a scored report: negotiated algorithms, inferred ESP suites, and
findings with severities and citations.

---

## Step 6 — Open the dashboard

```bash
python -m cipherguard.cli serve
```

Then open **http://127.0.0.1:8000** in your browser.

Pick a capture from the list and select **Assess capture**. Leave the
terminal running; `Ctrl-C` stops the server.

The page needs no internet connection: its fonts, script and styles are all
served from your machine.

---

## The demo sequence

Seven short steps that show each part of the tool.

**1. A broken gateway and a hardened one, side by side**

```bash
python -m cipherguard.cli analyze samples/legacy.pcap
python -m cipherguard.cli analyze samples/hardened.pcap
```

**2. Downgrade detection — the thing no single capture can see**

```bash
python -m cipherguard.cli watch samples/hardened.pcap  --db fleet.db
python -m cipherguard.cli watch samples/downgrade.pcap --db fleet.db
```

The second command prints a downgrade from 128 bits to 80 bits on the same peer
pair, and exits with code 3. Neither capture shows a problem on its own.

**3. Validation on traffic the project did not create**

```bash
./scripts/fetch-real-captures.sh          # Windows: powershell -ExecutionPolicy Bypass -File scripts\fetch-real-captures.ps1
python -m cipherguard.cli verify-real -v
```

Five real IKE captures from the Wireshark project, checked against the
algorithms their filenames state. Needs internet the first time. These contain
IKE handshakes only, so they validate the dissector, not ESP inference.

**4. What the learned models contribute**

```bash
python -m cipherguard.cli validate
```

On independently generated traffic the learned models alone reach 73.7%
framing-class accuracy; with the RFC 4303 arithmetic applied it is 100%. The
models overfit the generator they were trained on, and the arithmetic is what
carries the result.

**5. Post-quantum roadmap**

```bash
python -m cipherguard.cli roadmap samples/backbone.pcap --data-class strategic
```

**6. Machine-readable inventory**

```bash
python -m cipherguard.cli cbom samples/backbone.pcap -o fleet-cbom.json
```

**7. Hardening config**

```bash
python -m cipherguard.cli remediate samples/backbone.pcap -o hardening/
```

---

## Optional — live capture

Linux only, and needs `CAP_NET_RAW`. Grant it narrowly rather than running the
whole analyzer as root:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
python -m cipherguard.cli sensor eth0 --window 60 --windows 3
```

Check first whether your host can do it at all:

```bash
python -c "from cipherguard.capture.live import available; print(available())"
```

Evidence retention is bounded by default (24 windows, 4 GB, 512 MB per window).
Add `--no-evidence` to assess and discard.

---

## Optional — run the tests

```bash
pip install -e ".[dev]"
python -m pytest tests/ -q
```

About 470 tests, about 4 minutes. Fourteen need the real captures and skip
until step 3 of the demo sequence has fetched them. The first run trains a
small model, so it is slower.

---

## Optional — an agency policy overlay

```bash
python -m cipherguard.cli analyze samples/transitional.pcap \
    --policy docs/example-policy.json
```

The same capture scores 48/100 under the NIST baseline and 28/100 under a
stricter 3072-bit directive, with no code change.

---

## If something goes wrong

| Symptom | Cause and fix |
|---|---|
| `No such file: samples/backbone.pcap` | The samples were removed. `python -m cipherguard lab` |
| Findings appear but no ESP suites | No model in `models/`. `python -m cipherguard train` |
| `unrecognised Host header` | Without a token the server answers `127.0.0.1` and `localhost` only. Open it by one of those, or name the host with `--allowed-host` |
| Port 8000 is already in use | Another program has it. `cipherguard serve --port 8001`, or `launch_dashboard.bat --port 8001` |
| The dashboard asks for an access token | The server was started with `CIPHERGUARD_TOKEN` (or `launch_dashboard.bat --lan`). The token is printed where it was started |
| `too many failed attempts` | Ten wrong tokens lock that browser's address out for a minute. Wait, then enter the right one |
| `externally-managed-environment` from pip | You skipped the venv in step 2 |
| `ModuleNotFoundError: cipherguard` | You are in the wrong directory, or the venv is not activated |
| Dashboard shows "Backend unreachable" | The `serve` process stopped; check that terminal |
| Dashboard is unstyled | Serve it via `cipherguard serve`, not by opening `index.html` directly |
| `model schema` error | Feature code changed since training. `python -m cipherguard.cli train` |
| `sensor` refuses to start | Missing `CAP_NET_RAW`, or not Linux. See the live-capture section |
| `serve --host 0.0.0.0` refused | Intentional: the API is unauthenticated. Set `CIPHERGUARD_TOKEN` first |

---

## Where things live

```
cipherguard/
├── cipherguard/
│   ├── dissector/      IKE and ESP parsing, pcap I/O
│   ├── ml/             features, models, validation
│   ├── audit/          policy baseline and rules
│   ├── intel/          baseline store, post-quantum exposure
│   ├── capture/        live AF_PACKET capture
│   ├── export/         CycloneDX CBOM
│   ├── remediation/    vendor config synthesis
│   ├── api/            FastAPI backend + dashboard
│   │   └── static/     index.html, css/, js/
│   └── cli.py          command line entry point
├── tests/              pytest suite
├── docker/             strongSwan testbed
├── README.md           overview, quick start, measured results
├── METHOD.md           method, validation, limitations
└── OPERATIONS.md       CLI, dashboard, sensor, security posture
```


---

## Hosting it on GitHub Pages

GitHub Pages serves files, not processes, so the Python backend cannot run
there. The analysis is instead done ahead of time and written as JSON, and the
dashboard reads those files instead of calling the API. Every number on the
hosted page is real pipeline output — it is a pre-computed build, not a mock —
but it cannot analyse a capture a visitor uploads.

**1. Push the project to GitHub**

```bash
git init
git add .
git commit -m "CipherGuard: passive IPsec analyzer (SIH26160)"
git branch -M main
git remote add origin https://github.com/Git-huber2007/CipherGuard.git
git push -u origin main
```

**2. Turn Pages on**

Repository → **Settings** → **Pages** → under *Build and deployment*, set
**Source** to **GitHub Actions** (or **Deploy from a branch** -> `/docs`).

**3. That is all**

`.github/workflows/pages.yml` runs on every push to `main`: it installs, runs
the test suite, generates the captures, trains the model, builds the static
dashboard and publishes it. If the tests fail, nothing deploys.

Your site appears at `https://git-huber2007.github.io/CipherGuard/` after a couple of
minutes. Watch progress under the **Actions** tab.

**Preview locally before pushing**

```bash
cipherguard export-demo
python3 -m http.server -d docs 8080     # then open http://localhost:8080
```

`docs/` is committed so Pages can also deploy from the branch, but the workflow
does not publish that copy: it rebuilds `docs/` from the code on every push, so
the hosted page cannot drift away from the code that produced it.

### If you need the real backend online

A live instance that analyses uploaded captures needs a host that runs Python —
Render, Railway, Fly.io and Hugging Face Spaces all have free tiers that work.
Start it with a token, since the API is unauthenticated by default:

```bash
CIPHERGUARD_TOKEN=$(openssl rand -hex 32) \
  cipherguard serve --host 0.0.0.0 --port $PORT \
  --cors-origin https://git-huber2007.github.io
```

`--cors-origin` is what lets the Pages build call this backend from a browser;
cross-origin access is off for every origin that is not named. The bundled
`render.yaml` and Dockerfile follow the same rule: neither starts the server
until `CIPHERGUARD_TOKEN` is set.

On Windows, `launch_dashboard.bat` serves the dashboard to this machine only.
`launch_dashboard.bat --lan` serves other devices on the network and prints the
access token each browser is asked for.

The Pages build and a local server cover most uses between them: the first
needs nothing installed, the second assesses your own captures.
