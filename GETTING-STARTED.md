# Getting started

Five minutes from download to a running dashboard.

---

## Step 0 — What you need

- **Python 3.10 or newer** (`python3 --version`)
- Works on Linux, macOS and Windows. Live capture (`sensor`) is Linux-only;
  everything else runs anywhere.
- No Docker required. No root required, except for live capture.

---

## Step 1 — Unzip and enter the folder

```bash
unzip cipherguard.zip
cd cipherguard
```

You should see `cipherguard/`, `tests/`, `docker/`, `README.md`.

---

## Step 2 — Install dependencies

A virtual environment keeps this off your system Python.

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

The second install registers the `cipherguard` command. Without it every
`cipherguard ...` example below fails, and you would have to prefix each one
with `python -m cipherguard.cli`.

Takes about a minute. If `pip` complains on Debian or Ubuntu about an
externally-managed environment, you skipped the venv — go back and create it.

---

## Step 3 — Generate the sample captures

There are no `.pcap` files in the archive; they are generated so the archive
stays small and the captures are reproducible.

```bash
python -m cipherguard.cli lab
```

Writes four scenarios into `samples/`: a legacy IKEv1 gateway, a partially
modernised one, a hardened one, a mixed backbone, plus a downgrade capture.

---

## Step 4 — Train the inference model

```bash
python -m cipherguard.cli train
```

About one minute. Prints the accuracy figures and writes `models/`.

Expect **100% framing-class** and **~59% exact-suite** accuracy. The second
number is *supposed* to be low — several ESP suites are byte-identical on the
wire and cannot be told apart by anything. The README explains this; it is worth
reading before you demo.

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

Pick a capture from the dropdown and press **Assess capture**. Leave the
terminal running; `Ctrl-C` stops the server.

> The dashboard loads fonts from Google. Without internet it falls back to
> system fonts and looks slightly different — nothing breaks.

---

## The demo sequence

If you have five minutes in front of judges, run these in order.

**1. The contrast — catastrophic vs clean, same tool, same second**

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
pair, and exits with code 3. This is the strongest ten seconds you have.

**3. Real-world validation — it works on traffic we did not create**

```bash
./scripts/fetch-real-captures.sh
python -m cipherguard.cli verify-real -v
```

Five real IKE captures from the Wireshark project, validated against ground
truth from their filenames. Needs internet the first time. Finding two genuine
bugs this way is a better story than a clean run would have been.

**4. Honest accuracy — volunteer the limitation**

```bash
python -m cipherguard.cli validate
```

Shows the learned models alone reach ~74% on independently generated traffic
while the RFC arithmetic mask carries it to 100%. Saying "our ML overfit, and
here is the measurement" lands better than any number you could claim.

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
pip install pytest httpx
python -m pytest tests/ -q
```

151 tests, about 50 seconds (140 plus 7 real-capture tests that skip until step 3 of the demo sequence). The first run trains a small model, so it is slower.

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
| `No such file: samples/backbone.pcap` | Step 3 not run. `python -m cipherguard.cli lab` |
| Findings appear but no ESP suites | Step 4 not run. `python -m cipherguard.cli train` |
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
├── tests/              133 tests
├── docker/             strongSwan testbed
└── README.md           architecture, accuracy, limitations
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

The generated `docs/` output is gitignored on purpose: it is rebuilt in CI on
every push, so the hosted page cannot drift away from the code that produced it.
Committing it would let the two disagree silently.

### If you need the real backend online

A live instance that analyses uploaded captures needs a host that runs Python —
Render, Railway, Fly.io and Hugging Face Spaces all have free tiers that work.
Start it with a token, since the API is unauthenticated by default:

```bash
CIPHERGUARD_TOKEN=$(openssl rand -hex 32) \
  cipherguard serve --host 0.0.0.0 --port $PORT
```

For a hackathon, the Pages build plus a local demo on your own laptop is
usually the better combination: nothing to go wrong on the day, and a link you
can put on a slide.
