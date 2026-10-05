# Using and operating CipherGuard

The command line, the dashboard, the continuous sensor, and what the tool
does to protect itself. The [README](README.md) covers installation.

## Command line

| Command | Purpose |
|---|---|
| `analyze <capture>` | Assess a pcap/pcapng and print a scored report |
| `analyze … --fail-under 70` | Exit code 2 below a threshold, for CI gating |
| `analyze … --json -o report.json` | Machine-readable output |
| `analyze … --policy FILE` | Apply an agency policy overlay |
| `remediate <capture> -o out/` | Synthesise gateway hardening configuration |
| `watch <capture> --db fleet.db` | Record against baseline; exit 3 on downgrade |
| `watch … --fleet` | Print the fleet triage queue, weakest link first |
| `roadmap <capture> --data-class strategic` | Rank links by post-quantum exposure |
| `cbom <capture> -o bom.json` | Export a CycloneDX 1.6 CBOM |
| `train` | Retrain the ESP inference model |
| `sensor <iface>` | Continuous live capture, assessment and baselining |
| `sensor --check` | Report capture capability and interfaces |
| `verify-real` | Validate the dissector against real public captures |
| `validate` | Cross-model validation and the mask/model ablation |
| `lab` | Write reference testbed captures |
| `rules` | List the audit rule catalogue |
| `serve` | Run the assessment dashboard (this machine only, by default) |
| `serve --cors-origin URL` | Let a page served from that origin call the API; off otherwise |

## Example report

```
CipherGuard assessment: backbone.pcap
  1528 packets  |  4 IKE sessions  |  4 ESP SAs  |  0.19s

  Posture    4/100  grade E  [#...........................]
           11 critical  7 high  12 medium  3 low

  Negotiated IKE security associations (parsed from the wire)
    203.0.113.7 <-> 198.51.100.4   IKEv1   [cisco]
      3DES_CBC, PRF_HMAC_MD5, AUTH_HMAC_MD5, 1024-bit MODP

  ESP tunnels (inferred, payload never decrypted)
    203.0.113.7 -> 198.51.100.4  SPI 0xe88b7591  380 packets
      64-bit block cipher  (100% confidence)
      3DES-CBC / HMAC-MD5-96 or DES-CBC / HMAC-SHA1-96
      framing-identical; not separable passively

  Findings
    CRITICAL  IKE-002  IKEv1 Aggressive Mode
    CRITICAL  IKE-006  Prohibited Diffie-Hellman group 2 (1024-bit MODP)
    CRITICAL  ESP-001  ESP tunnel using 64-bit block cipher [inferred]
```

## Dashboard

`serve` runs it against the API; `export-demo` writes the same page as a static
site (the GitHub Pages build), with every analysis precomputed. The server does
the data work; the page renders what it is given.

- **Works offline.** IBM Plex is bundled under `static/fonts/` (SIL Open Font
  License alongside) instead of loaded from Google Fonts, so the page renders
  on an isolated network or from a static export opened with no internet
  connection. A test fails if `index.html` or `dashboard.js` references any
  external domain.
- **No outbound calls.** Neither the server nor the page contacts anything
  outside the machine by default. The one lookup that would (the public
  address and ISP shown beside the VPN status, asked of a third-party service)
  is off unless the operator sets `CIPHERGUARD_EGRESS_LOOKUP=1`, and uses HTTPS
  only. With it off the panel reads "Not queried"; it does not show a
  placeholder as if it were a result.
- **Light by default, dark on request.** A Theme picker in the masthead offers
  Light, Dark and System; the choice is kept per browser and applied before
  first paint (`static/js/theme-init.js`), so a dark OS no longer forces a
  dark page. Every text colour clears WCAG AA (4.5:1) against its actual
  background in both themes; `tests/test_contrast.py` checks the colour tokens.
  Motion is limited to what `prefers-reduced-motion` allows.
- **Plain language.** Terms such as IKE, ESP, AEAD, Sweet32 and CRQC are marked
  with a dotted underline. Their definitions come from `static/glossary.json`
  and show on hover, keyboard focus or tap. Every finding group also carries a
  one-sentence "why this matters", written server-side per rule
  (`audit/plain.py`).
- **Compare two captures**: score, grade, severity counts, each link's
  strength and each negotiated suite, with every difference marked as
  improved, worse or changed. It defaults to
  `legacy.pcap` against `hardened.pcap`, and works in the static build.
- **Presentation mode** (the *Present* button, or `?present` in the URL). It
  uses larger type, shows one step at a time, and steps with ← / →: posture
  score, wire ribbon, worst link, top finding group, hardening plan. Esc exits.
- **Downloads and provenance.** Download the JSON report, the CycloneDX CBOM
  and the hardening config, and copy the config with a confirmation that says
  whether the copy worked. A provenance panel shows the capture's SHA-256, the
  model manifest's hash and training date, and the report digest, all computed
  on the server.
- **Only what was measured.** The page shows no simulated panels: the Q-Day
  cockpit, canned hex inspector, MITRE heatmap, compliance score and Wi-Fi
  threat simulator were removed, along with the server's
  `/api/wifi/simulate-rogue` endpoint. The static build labels its Wi-Fi view
  as an example scan of invented networks; a scan of a real site is never
  bundled or published.
- **Live capture is live, or it says it is not.** *Start* opens a receive-only
  raw socket on the machine running the server and keeps IKE and ESP only. That
  needs Administrator on Windows or `CAP_NET_RAW` on Linux; without it the
  panel reports that the capture could not start, and why. *Replay samples* is
  a separate button that plays back the bundled sample captures. The status
  reads "REPLAY · SAMPLES, NOT LIVE", a notice stays on the panel, the snapshot
  is saved as `replay_snapshot.pcap`, and an assessment made from it carries a
  banner saying so. Rates are computed from the bytes seen.
- **Upload** a capture by file picker or by dropping it on the page. The control
  appears only when the server reports uploads enabled (never in the static
  build), and errors show the server's own reason, such as the size limit or a
  duplicate name.
- **Demo-safe.** If a request fails, the last good result stays on screen,
  labelled as the previous result, with one calm line and a Retry button. The
  full error goes to the browser console. Panels show placeholder blocks while
  an assessment runs; they are static when reduced motion is requested.

---

## Deployment: continuous sensor mode

Continuous assurance requires live, persistent monitoring rather than scheduled
batch file inspections. The `sensor` command enables real-time monitoring:

```bash
cipherguard sensor --check          # Capability and interface inspection
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
cipherguard sensor eth0 --window 300 --db fleet.db --audit-log /var/log/cg.jsonl
```

```
Sensor on eth0  ·  300s windows  ·  baseline fleet.db
  Receive-only socket; Ctrl-C to stop

  [06:47:07] window 1: 18/100 E  1 SA  0 ESP  30 packets
  [06:52:07] window 2: 74/100 C  3 SA  4 ESP  184203 packets
      DOWNGRADE 198.51.100.77|203.0.113.55: 128 -> 80 bits
```

`setcap` on the interpreter is fine for trying the sensor out, but it grants raw
sockets to every Python program on the host. For a standing deployment use the
systemd unit below, which grants the capabilities to this one service only.

Capture uses Linux `AF_PACKET` with a hand-assembled classic-BPF program to filter
IKE and ESP frames in-kernel, avoiding third-party libpcap bindings and eliminating
userspace copy overhead for non-IPsec traffic.

Evidence retention is strictly bounded: `--retain 24` windows, `--max-disk-mb 4096`
total, and `--max-window-mb 512` per window. Use `--no-evidence` to assess and discard
frames in memory where packet retention is not authorized.

Two architectural guarantees are enforced:
1. **Receive-only operation**: The capture socket cannot transmit or inject frames onto monitored segments.
2. **Loss transparency**: Kernel packet drop counts are monitored and reported directly alongside posture scores to ensure dropped frames never silently distort an audit.

### Running unattended

A sensor is meant to run for weeks with nobody watching it. That requires two
things: everything it writes has to be bounded, and something outside it has to
be able to tell whether it is still working.

**Everything that grows per window is bounded.** Each ceiling also protects the
evidence behind the most recent assessment:

| Grows every window | Bound (sensor flags, defaults) | Never deleted |
|---|---|---|
| Window captures | `--retain 24` files, `--max-disk-mb 4096` | The capture behind the most recent assessment, even if that one window exceeds the byte cap. Before this change, a single oversize window deleted itself right after it was assessed. |
| Baseline observations | `--retain-observations 500` per link, `--retain-days 90` | The row that established each link's current baseline (the evidence behind "was N bits" in a downgrade alert). Also each baselined link's latest row, so a link that has gone quiet stays in the fleet view, and every row of the most recent assessment, even across a clock step. |
| Audit log | `--audit-max-mb 16`, `--audit-backups 5` (`audit.jsonl.1` … `.5`) | The most recent record. Rotation runs before the write, so the record that triggers it lands in the fresh file. |

Both sensor loops (the `cipherguard sensor` command and the library
`capture.sensor.run`) share one retention implementation and use the same
defaults.

Peers that never earned a baseline (withheld by the new-peer rate limit, which
is what spoofed addresses look like) get no protection and age out completely.
Existing baseline databases are migrated when opened.

Audit appends and rotation run under an OS file lock (`audit.jsonl.lock`), so
the sensor, the dashboard and an analyst's CLI can share one log. Each rotation
step is an atomic `os.replace`. The regression test runs four processes
appending through about 20 rotations and requires every line intact and present
exactly once. During development the same harness was run with the lock
removed: six writers produced 498 of 1,800 lines plus two torn ones, and five of
the writers crashed on Windows sharing violations.

**Health is checkable from outside.**

```bash
cipherguard --models /var/lib/cipherguard/models healthcheck \
  --out /var/lib/cipherguard/captures --db /var/lib/cipherguard/baseline.db \
  --audit-log /var/log/cipherguard/audit.jsonl
echo $?        # 0 healthy · 1 degraded · 2 failed   (--json for machines)
```

| Check | Failed (exit 2) | Degraded (exit 1) |
|---|---|---|
| `model` | Files don't match `MANIFEST.sha256`, the manifest is missing, or the feature schema changed. The sensor would die at load time on every window. | No model installed (ESP inference disabled) |
| `baseline_db` | The store exists but can't be written (probed with a rolled-back write), or isn't a database | Locked for more than 5 s |
| `disk` | Free space is less than the part of the retention ceiling not yet used (evidence cap + one in-flight window + every audit generation) | Less than 20% margin over that, or audit rotation disabled |
| `last_window` | The last completed window is older than three times the stale threshold | Older than the stale threshold (two windows + 120 s by default, or `--stale-after`), no window recorded yet, or a timestamp in the future |

The sensor records every completed window, including quiet ones with no IPsec
traffic, in `<out>/.sensor-state.json`. It writes that file atomically, so a
live process that has stopped completing windows shows up as stale. The
healthcheck never unpickles the model and never creates the database. Pass it
the same storage flags as the sensor so it checks the real configuration.

**systemd.** [deploy/cipherguard-sensor.service](deploy/cipherguard-sensor.service)
runs the sensor as a dedicated `cipherguard` system user. Its settings:

- Capabilities: `CAP_NET_RAW` and `CAP_NET_ADMIN` only, as both the ambient and
  the bounding set, with `NoNewPrivileges`.
- Filesystem: `ProtectSystem=strict`, with writes allowed only under
  `ReadWritePaths=/var/lib/cipherguard /var/log/cipherguard`.
- Sandboxing: `ProtectHome`, `PrivateTmp`, `PrivateDevices`, and the kernel
  protections. Address families are limited to `AF_PACKET AF_UNIX AF_NETLINK`,
  because the sensor never opens an IP socket.
- Restarts: `Restart=on-failure`, capped at five starts in ten minutes, so a
  model that fails its manifest check doesn't loop forever.
- Backstop: `MemoryMax=2G`.

A test parses `ExecStart` with the real CLI parser and checks that every path
the sensor writes is inside `ReadWritePaths`. The unit has **not** been started
under systemd or checked with `systemd-analyze verify`, because this project was
developed on Windows. Treat the first start on a Linux sensor as its first real
test.

#### Soak test

[scripts/soak.py](scripts/soak.py) replays captures through the same per-window
steps as `cipherguard sensor`: stage the window, analyze (reloading and
re-verifying the model each time, as the sensor does), audit log, baseline
store, evidence pruning, state file. It samples RSS, open descriptors, baseline
DB size and rows, audit log size across generations, and retained evidence. It
exits 1 if any of these exceeds its stated bound, or if retention ever removes
the most recent assessment's capture or audit record. It does **not** exercise
live `AF_PACKET` capture.

```bash
python scripts/soak.py --duration 3600 --json-out soak.json
```

CI runs two soak tests:

- A 60-second variant, which requires that observation pruning, evidence
  pruning and log rotation all actually ran. A bound that is never reached
  proves nothing.
- A 20-second run with an injected 4 MB-per-window leak, which must fail on RSS
  and on nothing else. This checks that the detector detects.

**What has actually been measured: one 30-minute run.** No longer soak has been
run, so the claim is "flat for 30 minutes of accelerated windows", not "stable
for weeks".

| | |
|---|---|
| Command | `python scripts/soak.py --duration 1800 --sample-every 10 --warmup 60` (default bounds) |
| Host | Windows 11 laptop, Python 3.11.9. Not Linux, not under systemd |
| Input | The six captures in `samples/`, cycled |
| Wall time | 1,822 s. About 90 s of that was the laptop in Modern Standby (13:39:18–13:41:08 in the system event log), when the process made no progress. Roughly 29 minutes of actual running. |
| Windows processed | 7,882 (4.3 per second, each a full analyze with model reload) |
| Samples | 175, of which 169 were after the 60 s warm-up |

| Metric | After warm-up | Bound | Result |
|---|---|---|---|
| RSS | 167.0 – 178.2 MB; peak 0.5 MB above the warm-up peak; ended at 174.8 MB | +48 MB | pass |
| Open handles (Windows) | 689 – 698; never above the warm-up peak of 705 | +16 | pass |
| Baseline DB | 84 rows, 57,344 bytes, identical in every sample from t=30 s to the end | rows ≤ peers × (20 + 1) = 84; 4 MB | pass |
| Audit log, all generations | 47 – 63 KB across 4 files | 65,536 bytes | pass |
| Retained evidence | 5 files, ≤ 3.2 MB | 5 files; 4 MB + one window | pass |
| Latest-assessment evidence and audit record | present after every one of 7,882 windows | — | 0 violations |

In that run, retention was working the whole time rather than sitting idle
below its limits: 10,427 observation rows pruned, 7,877 window captures pruned,
and 394 audit log rotations. The per-window rate is far above a real sensor's
(one window per 60–300 s), so 7,882 windows is roughly 5½ days of 60-second
windows or 27 days of 300-second windows. But it compresses only the per-window
work. It says nothing about wall-clock effects such as the 90-day age ceiling,
long-lived kernel sockets, or real traffic. The retention settings were
deliberately small (20 rows per link, 16 KiB log files) so that steady state
was reached within seconds. The production defaults are larger but use the
same code paths.

## Retargeting the policy

An agency's national cryptographic directive often differs from the default NIST baseline
(for example, mandating a 3072-bit Diffie-Hellman floor where NIST permits 2048-bit).
CipherGuard supports version-controlled policy overlays without modifying engine source code:

```bash
cipherguard analyze capture.pcap --policy agency-directive.json
```

```json
{
  "name": "Example national directive",
  "reference": "AGENCY-CRYPTO-DIRECTIVE-2026 s4",
  "MIN_DH_BITS": 3072,
  "MAX_IKE_SA_LIFETIME": 28800,
  "DH_PROHIBITED": { "14": "2048-bit MODP is below the national floor" },
  "ENCR_PROHIBITED": { "ENCR_AES_CBC": "AEAD only under the directive" }
}
```

The exact same capture evaluated under different policies demonstrates strict compliance enforcement:

| Policy Baseline | Score | DH Group 14 Status |
|---|---|---|
| NIST SP 800-77 Rev. 1 baseline | 48/100 (D) | Accepted |
| Example agency 3072-bit directive | 28/100 (E) | **Critical finding** |

Policy overlays extend the baseline by default, ensuring all standard cryptographic checks
remain active unless explicitly reconfigured. Unknown configuration keys fail immediately
to prevent misspellings from silently bypassing security checks.

## Operating it in production

| Concern | Provision |
|---|---|
| API authentication | Opt-in bearer token, verified with constant-time `hmac.compare_digest` (a plain `==` returns early on the first differing byte and leaks timing prefixes). `/api/health` stays open for load balancer probes. |
| Custody and accountability | JSON Lines audit trail: records assessor identity, timestamp, and capture SHA-256 (findings are logged as rule ID and subject only, preventing duplicate intelligence leakage). |
| Model provenance | Every model records training time, library versions, corpus and a feature-schema hash. |
| Silent feature drift | Loading refuses if the schema hash differs. This is the failure that matters: array shapes stay compatible, the model loads, and predictions are quietly computed from columns that no longer mean what the model was fitted on. Nothing raises and the output looks plausible. |
| Network exposure | Non-loopback binds refused unless authenticated or explicitly overridden. `launch_dashboard.bat` listens on `127.0.0.1`; `launch_dashboard.bat --lan` binds the network and always sets a token, which it prints. The Dockerfile and `render.yaml` start the server without the override, so a container or hosted instance does not start until `CIPHERGUARD_TOKEN` is set. |
| Cross-origin access | Off by default. `--cors-origin` (or `CIPHERGUARD_CORS_ORIGINS`) names the origins allowed to call the API from a browser; a wildcard is rejected. The hosted static page reaching a local engine is the one case that needs it. |
| Outbound calls | None by default. `CIPHERGUARD_EGRESS_LOOKUP=1` enables the public-address lookup beside the VPN status. |
| Resource bounds | Flow-table capacity limits, capture length validation, upload ceilings. |
| Unattended operation | Observation retention, audit log rotation, evidence retention that never removes the latest assessment's capture, `cipherguard healthcheck` (exit 0/1/2), a sandboxed systemd unit, and a soak test. See [Running unattended](#running-unattended) below. |

```bash
CIPHERGUARD_TOKEN=$(openssl rand -hex 32) \
  cipherguard serve --host 0.0.0.0 --audit-log /var/log/cipherguard.jsonl
```

## Security posture of the analyzer itself

A tool that ingests hostile traffic is itself an attack surface, and a monitoring
system that can be knocked over is worth attacking: blinding the auditor is a
useful precursor to doing something else. Findings from an audit of this
codebase, all fixed and covered by regression tests:

| Issue | Impact | Fix |
|---|---|---|
| Unbounded ESP flow table keyed on the attacker-chosen 32-bit SPI | 60k spoofed packets created 60k records and 68 MB. Seconds of line-rate traffic exhausts the sensor. | Capacity cap with least-active eviction, so floods of singletons are dropped before established tunnels. Eviction count is reported so the audit can say its view was incomplete. |
| **That cap then became a CPU denial of service** | Evicting one flow per new key meant every packet of an SPI-randomised flood triggered a full 8192-entry scan — the table never fell below capacity so the scan never stopped. Throughput collapsed **158,000 → 909 pkt/s (175x)**. The memory bound held perfectly while the sensor stopped keeping up with the link: the same attack, moved from RAM to CPU. | Batched `heapq.nsmallest` eviction of the weakest 10%, amortising the scan. Measured back to **178,000 pkt/s**. Guarded by a wall-clock regression test. |
| `joblib.load` on an unsigned pickle | Write access to `models/` was code execution inside the analyzer, often the most privileged process on the sensor. The feature-hash check did not help because it reads `meta.json` from the same directory. | SHA-256 manifest verified **before** the unpickle. Not a signature and does not claim to be; it detects tampering by anything that cannot also rewrite the manifest, and gives operators a hash to pin. |
| One spoofed packet could write a fleet baseline | `negotiated()` fell back to the first *offered* proposal, so an unanswered `IKE_SA_INIT` (which anyone on a mirrored segment can send) permanently set a peer pair's reference point. Set it high and real downgrades never fire; set it low across many pairs and the alert flood trains operators to ignore exit code 3. | Baselines record only responder-confirmed proposals, promote after repeat observation, and rate-limit new peer keys. |
| Capture readers trusted in-file length fields | A 140-byte file declaring a 3 GB packet is a 20-million-fold memory amplification. | Every length validated against a snaplen ceiling *and* the bytes actually remaining in the file. |
| Baseline DB path accepted as an API query parameter | The store opens the path as SQLite and creates parent directories: unauthenticated arbitrary-directory creation and file probing. | Path is fixed at application construction; the endpoint takes no parameters. |
| Capture filename interpolated into generated router config | A name containing a newline ends the comment, and the remainder becomes a live configuration directive an operator pastes into a gateway. | All untrusted text flattened and length-bounded before it enters generated config. |
| Upload endpoint unbounded, overwriting, path-rewriting | Disk exhaustion; silent destruction of evidence a prior assessment relied on. | 500 MB cap enforced from `Content-Length` before the body is read, a 4 GB ceiling on the capture directory, a pcap/pcapng magic-number check, partial-file cleanup, 409 on existing names, explicit rejection of path-bearing names rather than silent `basename()` rewriting. |
| Dashboard unauthenticated on any bind address | Publishes a map of which national links are cryptographically weak: exactly the targeting information an attacker wants. | Non-loopback binds refused unless explicitly overridden. |
| **The project's own launchers used the override** | `launch_dashboard.bat`, the Dockerfile and `render.yaml` all started the server on `0.0.0.0` with `--insecure-bind` and no token. The refusal above was correct and every shipped way of starting the server switched it off. | The launcher binds loopback, and its `--lan` mode generates a token. The Dockerfile and `render.yaml` dropped the override, so the server's own refusal applies to them. |
| Every origin allowed to read the API | CORS answered `*`. With the default tokenless loopback bind, any web page open in the analyst's browser could fetch `http://127.0.0.1:8000/api/fleet` and read which links are weak, or start a capture. The loopback bind was a boundary only against other machines. | No cross-origin access unless specific origins are configured; a wildcard is rejected at startup. |
| Packet stream had no token check | `/api/sniff/stream` was left unguarded because `EventSource` cannot send a header, so on an authenticated deployment the live packet feed (peers, SPIs, rates) was readable without the token. | Guarded like every other route. The page reads the stream with `fetch()` and sends the token in `Authorization`; it is never put in the URL. A test fails if any `/api/` route other than `/api/health` lacks the guard. |
| Outbound lookups by default | The server asked four public services for the sensor's address on every dashboard load, one over plain HTTP, and the page asked one itself in static mode. That discloses where the sensor sits and contradicts the offline guarantee. | Off unless `CIPHERGUARD_EGRESS_LOOKUP=1`, HTTPS only. The page's own lookup is removed. |
| Sample traffic presented as a live capture | When the raw socket could not be opened (any unprivileged workstation), the sniffer silently replayed the sample captures and the page labelled them live. On the live path it also counted every UDP datagram on the host as ESP, read port numbers as an SPI, buffered all of the host's traffic for the snapshot, and reported throughput as packets × 800 bytes. | A capture that cannot start reports the failure and the reason. Replay runs only on an explicit request and is labelled everywhere. The live path keeps IKE and ESP only and computes rates from bytes seen. |
| Plan approval gated nothing | `/api/remediation/{id}/apply` staged any plan, approved or not; an approval with no name was recorded as "Security Administrator"; and staging overwrote the approver. | Staging requires an approved plan (409 otherwise). An approval needs a name, which is stored and shown as self-declared. Approvals and dry-runs are written to the audit log by plan ID, without the configuration text. |
| Other web sites could drive the tokenless server | A `text/plain` POST needs no preflight, so any page open in the analyst's browser could start a capture, write a snapshot into the capture directory, trigger Wi-Fi scans or record a plan approval under a name of its choosing. CORS only stops the response being read. | State-changing requests carrying another site's `Origin` are refused, and a JSON body must be declared as `application/json`. |
| No check on the `Host` header | Under DNS rebinding a hostile page is same-origin with `127.0.0.1` as far as the browser is concerned, so CORS never applies and the whole API was readable. | Without a token the server answers loopback names only; other names are added with `--allowed-host`. |
| A client could switch off every rule unseen | `disabled` on `/api/analyze` took any list. The weakest lab capture scored 100/A with no findings, and neither the report nor the audit log said why. | Only known rule IDs are accepted, and the rules switched off are recorded in the report and in the audit log. |
| No response security headers | The page could be framed, and nothing restricted what it could load or run. | A content security policy (scripts from the server's own files only), `nosniff`, frame denial, a referrer policy, and HSTS when served over HTTPS. The page uses no inline script. |
| Token guessing was unthrottled | 300 wrong tokens were answered in under two seconds. | An address is locked out for a minute after ten wrong tokens; the routes that analyse, write or run OS commands are rate limited per client. |
| The interactive API docs were public | `/docs` and `/openapi.json` were served without the token, and `/docs` loaded its scripts from a CDN, against the no-outbound-calls rule. | Not served. |
| The page sent the token to a second server | A failed request was retried against `http://127.0.0.1:8000` with the `Authorization` header attached, whatever was listening there. The hosted static page also probed that address on every visit. | The page talks to one server: its own origin, or the one saved in the Server dialog. |
| Malformed input reached the client as a bare 500 | An unreadable capture, a non-hex SPI, an over-long filename and a non-ASCII token all raised. | Each is a 4xx that says what was wrong. Unexpected errors are logged on the server and return no detail. |

Authentication and audit logging are implemented (`require_token` with
`hmac.compare_digest` on every route except `/api/health` and `/static`, plus
`core/audit_log.py`). Both are opt-in, and the loopback-only default is what
makes that safe by construction rather than by documentation. What is still
missing is TLS termination and per-user identity; the API is designed to sit
behind an authenticating reverse proxy for those. Until it does, the name on a
plan approval is whatever the caller typed, and the dashboard and the audit log
both label it self-declared.

## Legal and privacy posture

Mirroring production traffic carries custody, retention and privacy
obligations. CipherGuard is built to minimise that exposure: it retains flow
metadata only (lengths, sequence numbers, timings, entropy statistics) and
never writes payload bytes to disk or logs. It is passive throughout; there is
no code path that transmits to a gateway or applies generated configuration.
Deploy on mirror ports under the same authorisation that governs any other
lawful interception of the segment.
