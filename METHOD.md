# Method and validation

How CipherGuard reads what it reads, what it infers, how each claim was
measured, and where it stops. The [README](README.md) is the short version.

## The problem, stated precisely

An agency running hundreds of IPsec gateways needs to know which of them are
still negotiating broken cryptography. The conventional answer is to log into
each device and read its configuration, which needs credentials, needs a change
window, and goes stale the moment someone edits a policy.

Reading it off the wire instead runs into a hard structural limit that shapes
this entire design:

| What crosses the wire | Where it lives | Readable passively? |
|---|---|---|
| IKE SA proposal: cipher, PRF, integrity, DH group | `IKE_SA_INIT` (v2), Main/Aggressive Mode (v1) | **Yes**, cleartext |
| Peer identities, vendor IDs, notifies, lifetimes | Same messages | **Yes**, cleartext |
| **Child/ESP SA proposal**: algorithms protecting data | Inside encrypted `SK` payload of `IKE_AUTH` (v2), or Quick Mode (v1) | **No** |
| ESP payload | Protocol 50 | **No** |

So the algorithms guarding the IKE control channel are plainly visible, and the
algorithms guarding the actual traffic are not. Prior work sits on one side of
this line or the other: formal configuration verification proves policies
correct on paper but is blind on the wire, and encrypted-traffic classification
reads flow statistics while ignoring handshake structure.

CipherGuard spans it. It parses what is parseable, infers what is not, and is
scrupulous about labelling which is which: every ESP finding is marked
`inferred` and carries a confidence score, and no inferred finding is ever presented
as an observation.

---

## How ESP inference works

Not a black box. The dominant signal is arithmetic, straight out of RFC 4303 §2:

```
ESP payload = IV ‖ Enc(data ‖ padding ‖ pad_len ‖ next_hdr) ‖ ICV
```

The encrypted region is padded up to the cipher's block size, and to a 4-byte
boundary at minimum. So for block size `b`, IV length `iv` and ICV length `icv`,
**every** ciphertext length on that SA satisfies

```
len mod max(b,4) == (iv + icv) mod max(b,4)
```

That residue is a fixed fingerprint readable without any key. A second
observable pins it down further: the GCD of gaps between distinct packet
lengths recovers the padding boundary directly, which matters because the
residue test alone is one-directional; a flow padded to 16 bytes automatically
satisfies the 8-byte test, so AES-CBC would otherwise be indistinguishable from
3DES. Entropy supplies the third axis, separating ESP-NULL from real ciphers.

Three components consume those observables:

- **Random Forest** over 88 features: modulo profiles, length statistics,
  entropy, and inter-arrival timing.
- **1D-CNN** over the 64-point distribution profile, treating the modulo
  histograms as a periodic signal. Implemented directly in NumPy (~6k
  parameters), so a passive sensor on an isolated segment needs no
  deep-learning runtime.
- **A plausibility mask** applying the framing rules above as hard constraints.
  Suites failing them are zeroed regardless of what the models predict, and each
  exclusion carries a stated reason, which makes a finding defensible
  to an auditor rather than an opaque model output to be trusted on faith.

### Validation against real gateways

Every other figure in this project is measured against traffic the project
generated itself, which proves only that it agrees with its own assumptions.

```bash
./scripts/fetch-real-captures.sh
python -m cipherguard.cli verify-real
```

Five real IKE exchanges from the **Wireshark project's test suite**, produced by
real implementations (a Windows IKE stack among them) and captured off real
networks. The ground truth is genuinely external: Wireshark names each file
after the algorithm it negotiates (`ikev2-decrypt-aes256gcm16.pcap`), so the
expected result comes from upstream maintainers rather than from anything
written here.

| Capture | Parsed | Verdict |
|---|---|---|
| `ikev2-decrypt-aes256gcm16.pcap` | AES-GCM-16-256, no INTEG, group 19 | 81/100 |
| `ikev2-decrypt-aes256gcm8.pcap` | AES-GCM-8-256, no INTEG, group 19 | 81/100 |
| `ikev2-decrypt-aes128ccm12.pcap` | AES-CCM-12-128, no INTEG, group 19 | 81/100 |
| `ikev2-decrypt-aes192ctr.pcap` | AES-CTR-192 **with** HMAC-SHA2-512-256 | 81/100 |
| `ikev1-certs.pcap` | IKEv1 3DES/MD5/group 2, Windows, 10 vendor IDs | **18/100** |

**5/5 validated.** The AEAD contrast is the sharpest check: GCM and CCM carry no
INTEG transform, whereas CTR must carry one (confirmed against real implementations
rather than against our own encoder).

#### What the arithmetic alone achieves

Running the RFC 4303 constraints with **no learned model at all**, on the field
corpus:

| | |
|---|---|
| Flows resolved to a single framing class | **92.2%** |
| ...and that class was correct | **92.2%** |
| Wrong answers whenever it resolved | **0** |
| Mean surviving suites | 2.9 of 9 |

The arithmetic never produces a wrong answer: it either resolves a flow or
declines to. The learned models handle the residual 8% and rank within a class,
which is a narrower job than the headline accuracy implies.

#### Calibration

An audit tool that prints "78% confidence" is making a claim, and a finding
carrying a number nobody checked is worse than one carrying none.
**ECE = 0.006** over framing-class confidence:

| Stated confidence | n | Mean stated | Observed accuracy |
|---|---|---|---|
| 0.8 – 0.9 | 11 | 0.879 | 1.000 |
| 0.9 – 1.0 | 259 | 0.999 | 1.000 |

#### Two bugs this found that synthetic traffic never could

**IKEv1 encryption flag.** Real Main Mode sets the Encryption bit from message
five onward. The payload walker treated the ciphertext as a payload chain and
raised six parse errors against a perfectly valid exchange. The generator only
ever emitted cleartext Main Mode, so no synthetic capture could surface it.

**IKEv1 algorithm names bypassed policy.** The prohibition tables held only
IKEv2 spellings (`ENCR_3DES`), so a real IKEv1 gateway negotiating `3DES_CBC`
never triggered the encryption rule at all. The generator and the policy shared
one vocabulary, so they agreed with each other and both were wrong. That capture
scored 24/100 before the fix and 18/100 after.

Neither was findable without external traffic. That is the argument for this
section existing.

### Validating ESP inference against real captures with sidecar labels

The ESP suite is negotiated inside encrypted `IKE_AUTH`, so nothing on the wire
can label an ESP flow without endpoint configuration. CipherGuard supports
user-supplied sidecar labels in `<capture>.label.json`:

```json
{
  "source": "swanctl --list-sas on the responder",
  "flows": [
    {"spi": "0xc3a1f00d", "suite": "AES-GCM-256 (ICV 16)"},
    {"peers": ["203.0.113.10", "198.51.100.20"], "suite": "AES-CBC-128 / HMAC-SHA1-96"}
  ]
}
```

Validate labelled captures at framing-class level:
```bash
cipherguard label-check path/to/capture.pcap
```

Or run `cipherguard verify-real`, which reports IKE and ESP validation separately.

To include labelled real captures in training with **leave-one-capture-out** evaluation:
```bash
cipherguard train --include-real samples/real/
```
Provenance is stored in `models/meta.json` with exact counts of real vs synthetic flows.

### Cross-model validation: breaking the circularity

Same-model held-out accuracy has a problem worth naming rather than glossing:
the classifier is trained on flows from the RFC framing model and evaluated on
flows from the RFC framing model. Held-out samples control for overfitting to
specific *draws*, not to the *model*. If the generator's assumptions are wrong,
training and test are wrong in identical ways and the evaluation cannot see it.

So there is a second, independent generator (`lab/fieldmodel.py`) built to
disagree — empirical trimodal Internet packet sizes instead of a smooth mixture,
bursty Pareto arrivals instead of exponential, packet loss and reordering,
transport as well as tunnel mode, and TFC padding regimes including pad-to-MTU,
which collapses the length distribution almost flat. What it does *not* vary is
RFC 4303 framing arithmetic, because that is the protocol, not an assumption.

```bash
cipherguard validate
```

| | Same-model | Cross-model |
|---|---|---|
| Framing-class accuracy | 100.0% | **100.0%** |
| Exact-suite accuracy | 60.6% | 55.9% |

Accuracy holds at 100% under 5% packet loss, reordering, transport mode and
pad-to-MTU. But the aggregate hides the finding that matters, which the
ablation exposes:

| Configuration | Framing-class accuracy on field data |
|---|---|
| Learned models alone (mask disabled) | **73.7%** |
| With the RFC 4303 plausibility mask | **100.0%** |

**The machine learning did overfit the generator.** Off-distribution it loses a
quarter of its accuracy, and the deterministic framing constraints are what hold
the result up. Reporting 100% as an ML result would have been a straightforward
misattribution; the honest claim is that a hybrid design survives distribution
shift specifically because half of it is arithmetic that cannot drift.

That is also the engineering argument for the architecture, and it is the answer
to the obvious judging question: what happens on traffic you did not generate.

### Measured accuracy, and its ceiling

Held out, 360 flows the model never saw, through the complete inference path:

| Metric | Result |
|---|---|
| **Framing-class accuracy** | **100.0%** |
| Exact suite accuracy | 60.6% |
| Random Forest alone, no mask | 53.2% |
| 1D-CNN alone, no mask | 50.2% |
| Both models combined, no mask | 54.7% |

The gap between those two top numbers is not a defect to be engineered away;
it is an information-theoretic limit, and reporting only the high number would
misrepresent what the tool knows. **AES-GCM-128, AES-GCM-256, AES-CTR and
ChaCha20-Poly1305 all produce byte-identical ESP framing** (IV 8, ICV 16,
4-byte alignment). Nothing observable distinguishes them, so exact-suite
accuracy is capped near 60% by construction. Likewise DES and 3DES.

What matters operationally is that every member of an indistinguishable group
carries the *same audit verdict*. So the engine reports the class, and a finding
reads:

> Packet framing on this SA matches block 8, IV 8, ICV 12, which identifies
> 3DES-CBC / HMAC-MD5-96 **or** DES-CBC / HMAC-SHA1-96 (framing-identical, not
> separable passively). 64-bit block size is vulnerable to Sweet32…

Both candidates are prohibited, so the verdict is certain even though the label
is not. Cross-class confusion in the held-out evaluation is **zero**.

---

## Beyond point-in-time scanning

Four capabilities separate a continuous assurance system from a scanner. Each
closes a gap the literature survey identified.

### 1. Temporal baseline and downgrade detection

A scanner asks "is this gateway misconfigured?" The more dangerous question is
"did this gateway *become* misconfigured?" No single capture can answer it,
because a weak suite in isolation looks like it was always the policy.

CipherGuard keeps a SQLite baseline of the strongest suite ever observed per peer
pair, and flags regression:

```
$ cipherguard watch samples/hardened.pcap --db fleet.db
  new link: 198.51.100.77|203.0.113.55 at 128 bits

$ cipherguard watch samples/downgrade.pcap --db fleet.db
  Cryptographic downgrade detected
    198.51.100.77|203.0.113.55
      was 128 bits (Curve25519, ENCR_AES_GCM_16-256, ESN, PRF_HMAC_SHA2_256)
      now  80 bits (1024-bit MODP, AUTH_HMAC_SHA1_96, ENCR_AES_CBC-128, PRF_HMAC_SHA1)
```

That signature (an on-path attacker stripping strong proposals, a failover onto
a legacy standby, or a botched firmware rollback) is invisible to a single capture
*and* to configuration review, which sees intended policy rather than what the
peers actually settled on. Exit code 3 makes it a CI/monitoring gate.

**Posture replay.** The dashboard can replay one link's recorded history, which
makes the detection visible rather than just described:

- **Timeline.** One mark per observation, with the negotiated strength drawn
  against the baseline each observation was compared with.
- **Downgrades** are drawn as ▼ with the bit delta.
- **Scrubber and Play control** step through the history. Stepping is discrete;
  the only motion is the cursor gliding between observations, and
  `prefers-reduced-motion` removes that.
- **Side-by-side detail.** At a downgrade, the baseline's transform set and the
  downgraded one are shown in two columns.

The marks are the detector's own verdicts. `record()` now stores what it
concluded for each observation (`new`, `steady`, `downgrade`, `unconfirmed`
until a stronger suite is seen again, `improvement` when promoted, `withheld`),
together with the baseline it compared against. The replay never re-derives
them, because a re-derivation would drift from the truth once retention had
pruned the rows that promotion counted. Observations recorded before this change
honestly show no verdict. The detection rules themselves are unchanged.

`GET /api/fleet/history?peer=<key>` serves the history. Its design:

- **Like `/api/fleet`:** behind the same token, with the database path fixed
  when the app is built.
- **One input:** a peer key, which must name a link already in the store. An
  unknown key returns 404 rather than an empty list, so peers withheld as
  possible spoofs can't be probed through it.
- **Read-only:** both fleet endpoints open SQLite with `mode=ro`. Previously
  `/api/fleet` used the normal constructor, which runs the schema script and
  migrations, so a page view could rewrite the sensor's database. A regression
  test checks the file is byte-for-byte unchanged after a GET.

The static build has no store, so `export-demo` runs the two commands above
into a throwaway database at export time and bakes the replay from what they
recorded, including their exit codes (0, then 3).

### 2. Security strength as a number, not an adjective

An agency with four hundred links needs an ordering, not a list of adjectives.
Every association is scored at its **weakest component**, which is where the
common real-world failure hides: AES-256 with SHA-1 and DH Group 2 reads as
"AES-256" on a configuration screen and is in fact an 80-bit association.

Two figures, because there are two adversaries. Grover halves symmetric key
lengths; **Shor zeroes every classical key exchange outright**, regardless of
modulus. That asymmetry is why key establishment must migrate long before bulk
encryption does, and expressing it numerically makes the argument unarguable.

### 3. Sweet32 quantified from observed throughput

"Don't use 3DES" is advice that loses to an operations team asking why the
outage window is justified. The same finding, computed from this link's actual
measured traffic:

> The negotiated cipher has a 64-bit block, so ciphertext blocks begin colliding
> after roughly 34.4 GB under a single key. With a 48-hour rekey interval this SA
> processes about 1091.79 GB per key, which is **31.775x the bound**. At the
> observed 50.55 Mbps this SA reaches the bound **91 minutes after each rekey**.

Same standard, same cipher, but now framed as an actionable change request.

### 4. Harvest-now-decrypt-later exposure and PQC sequencing

"Enable PQC" is not a plan. The quantum threat is *retroactive*, so exposure
depends on traffic volume, key-exchange recoverability, and how long the data
stays sensitive (which the tool cannot observe and takes from the
operator). Mosca's inequality then gives a deadline:

```
$ cipherguard roadmap samples/backbone.pcap --data-class strategic
  Mosca gap +41.0 years: data recorded today will still be sensitive
  when it becomes decryptable.

  1. [idx 10.4] 203.0.113.7 <-> 198.51.100.4
      64 classical / 0 quantum bits · 0.4 MB observed · 50.55 Mbps
```

Phase 1 fixes broken classical crypto (exposed to a conventional attacker
*today*, so the quantum timeline isn't the binding constraint). Phase 2 deploys
RFC 8784 pre-shared keys, which work on existing firmware. Phase 3 enables hybrid
ML-KEM under RFC 9370. The exposure index is a transparent weighted product,
documented in full so a reviewer can disagree with the weights rather than
reverse-engineer them.

**Recognising a link that has migrated.** A roadmap that recommends hybrid
ML-KEM has to be able to tell when a gateway has done it. Under RFC 9370 the
peers negotiate one or more *additional key exchanges* (transform types 6–12,
ADDKE1–ADDKE7) alongside the usual one, then run each in an encrypted
`IKE_INTERMEDIATE` exchange (RFC 9242) between `IKE_SA_INIT` and `IKE_AUTH`:

```
$ cipherguard analyze samples/pqc_hybrid.pcap
  Posture  100/100  grade A
    203.0.113.130 <-> 198.51.100.140   IKEv2   [strongswan]
      ENCR_AES_GCM_16-256, PRF_HMAC_SHA2_384, Curve25519, ADDKE1=ML-KEM-768, ESN
      hybrid key exchange (RFC 9370); 1 IKE_INTERMEDIATE exchange observed, contents encrypted
  No findings.
```

- **What is read.** The proposal and the responder's selection, both cleartext
  in `IKE_SA_INIT`, and the fact that `IKE_INTERMEDIATE` exchanges took place.
- **What is not.** The additional key exchange itself. Its public key and
  ciphertext are inside the encrypted payload, so the tool reports how many
  such exchanges it saw and nothing about what they carried. If an additional
  exchange was negotiated and none was seen (a capture that ended early), that
  is reported as an informational note, IKE-014.
- **Only the responder's selection counts.** An initiator that offers ML-KEM to
  a responder that picks the classical proposal has a classical link. The
  finding says the exchange was offered and not selected, and nothing credits
  the offer: not the finding, not the strength figure, not the roadmap. The
  same holds for an offer no response was seen to, and for `USE_PPK` sent only
  by the initiator. `samples/pqc_declined.pcap` is that case; it carries the
  same offer as the hybrid capture and gets the opposite verdict.
- **Strength.** A hybrid is scored at its strongest component against each
  adversary, because both shared secrets go into the keys and an attacker has
  to break both. Curve25519 with ML-KEM-768 is 192 bits of key exchange and
  192 against a quantum attacker; two classical groups together are still zero.
  The association is then bounded by its weakest other component as before, so
  a hybrid on a 128-bit cipher is reported as limited by the cipher, and the
  roadmap files it under "raise the cipher key", not "enable ML-KEM".

**The harvest clock.** The dashboard's post-quantum panel shows the same
arithmetic as two instrument readings:

- **Harvestable on quantum-exposed links.** This starts at the ESP bytes
  observed on those links in the capture. It then grows at their summed
  observed rate for as long as the view is open. The measured figure and the
  extrapolation are labelled separately, and the count runs from when the view
  opened, not from the capture time, so a months-old static export doesn't show
  months of invented traffic. With `prefers-reduced-motion` it moves in 5-second
  steps instead of running continuously.
- **Mosca deadline.** This shows years and months until the deadline, or how far
  past it, for the classification chosen in the selector. The browser
  recomputes it with a copy of `mosca_gap()`. The class table itself isn't
  copied; the roadmap publishes it (`assumptions.secrecy_lifetimes`). A test runs
  the JavaScript and Python formulas over a table of inputs under Node and
  requires identical doubles. Re-bracketing the JS as `s + (m − c)` makes that
  test fail.

The panel states on screen that the quantum arrival year is a planning
assumption, not a forecast, and shows how to substitute your own figure
(`--crqc-years`). Changing the classification moves only the deadline. The
exposure index values stay those of the class the capture was analysed under,
and the ranking order doesn't depend on the class.

### 5. CBOM export: inventory derived from traffic, not source

CycloneDX 1.6 added first-class cryptographic assets because PQC mandates
require organisations to inventory their cryptography. Every existing CBOM
generator derives that inventory from **source code or binaries** (telling you
what a device is *capable of*). CipherGuard derives it from **observed traffic**
(what a device is *actually doing*).

Those differ constantly in practice. A gateway compiled with AES-GCM support
that negotiates 3DES because of a stale peer policy is invisible to a
source-derived CBOM and obvious here.

```bash
cipherguard cbom samples/backbone.pcap -o fleet-cbom.json
#   CycloneDX 1.6 · 26 cryptographic assets (22 observed, 4 inferred)
#   16 vulnerabilities recorded
```

Every asset carries provenance. Inferred assets additionally carry confidence,
their framing signature, and the full candidate set. An inventory that cannot
distinguish measurement from inference is misleading exactly where it matters
most.

---

## Audit rules

Findings cite NIST SP 800-77 Rev. 1, RFC 8247, RFC 4303, RFC 9395 and
SP 800-131A Rev. 2.

**Observed** (parsed bytes): IKEv1 in use · Aggressive Mode · PSK
authentication · prohibited encryption · prohibited/deprecated integrity and
PRF · weak DH groups · **no quantum-resistant key establishment** · residual
downgrade surface · excessive SA lifetime · negotiation-failure patterns ·
fragmentation not negotiated · **weakest-link security level** ·
**quantified Sweet32 birthday exposure** · additional key exchange negotiated
but not observed (informational).

**Inferred** (ESP side-channel): prohibited framing class · payload entropy
below the ciphertext floor · anti-replay discontinuities · insufficient sample.

The downgrade-surface rule is worth calling out: it fires when a gateway still
*advertises* broken transforms even though this session selected a strong one.
Configuration review sees the same list and calls it acceptable; only wire
observation shows what is genuinely reachable.

Post-quantum readiness is treated as a live finding, not a footnote. Any SA
relying purely on classical Diffie-Hellman is flagged for harvest-now-decrypt-later
exposure, with remediation pointing at RFC 8784 pre-shared keys today and
ML-KEM hybrid groups (FIPS 203) as firmware allows. The finding is withdrawn
only on what a responder was seen to agree to: a post-quantum group as the key
exchange or as an RFC 9370 additional key exchange in the selected proposal,
or `USE_PPK` in a response.

---

## Reference testbed

`cipherguard lab` writes seven scenarios offline: a legacy IKEv1 Aggressive Mode
gateway, a partially modernised IKEv2 gateway, a hardened AES-GCM gateway over
NAT-T, the hardened pair later renegotiated weaker, a mixed backbone with
several gateways on one mirror port, an RFC 9370 hybrid (Curve25519 with
ML-KEM-768, including its `IKE_INTERMEDIATE` exchange), and the same hybrid
offer to a responder that selects the classical proposal. The IKE packets
are constructed from the RFC field layouts independently of the dissector, so a
misread field surfaces as a round-trip test failure rather than silently
agreeing with itself.

`docker/` additionally runs two real strongSwan gateways on an isolated bridge
with a passive sniffer, for calibration against genuine traffic:

```bash
cd docker && docker compose --profile lab up -d
docker compose exec sniffer /capture.sh weak 60
python -m cipherguard.cli analyze docker/captures/weak.pcap
```

---

## Tests

```bash
python -m pytest tests/ -q                 # 457 passed, 14 skipped without real captures
python -m pytest tests/ -q -m "not soak"   # skip the ~90 s of soak tests
```

Coverage includes pcap round-trips, IPv4 checksum validity, IKEv1/IKEv2
dissection against independently constructed packets, NAT-T marker handling,
graceful degradation on truncated frames, the framing-residue invariant across
every catalogued suite, scoring monotonicity, and policy-table consistency.

Robustness is fuzz-tested rather than assumed. **Robustness fuzzing**
(`tests/test_fuzz.py`) throws 10,000 mutated packets and 4,000 random inputs at
the dissector. The contract is absolute: `parse_message` returns a valid message
or `None`, records difficulties in `parse_errors`, and never raises, hangs, or
allocates without bound. Its input is chosen by an adversary (anyone who can put
a packet on the monitored segment supplies input directly), and real captures contain
malformed frames for benign reasons too: snaplen truncation, mid-transfer capture
start, and hardware offload artefacts.

Real-world protocol handling is covered explicitly: RFC 3948 NAT keepalives (a single
0xFF byte sent every 20 seconds by peers behind NAT), RFC 7383 IKE fragmentation on
certificate-bearing exchanges, and retransmission counting so a lossy link does not
artificially inflate negotiation metrics.

Also verified: weakest-link scoring, the fundamental invariant that **every classical key
exchange has zero quantum strength** (alone or in any combination of RFC 9370
additional key exchanges), Sweet32 scaling with observed volume,
direction-independent peer identity, temporal baselines retaining the best-ever cryptographic state
rather than merely the latest, Mosca sign conventions, and CycloneDX 1.6 CBOM structural validity
with full provenance on every asset.

Four are explicit regression tests for bugs made during development:

- the plug-in entropy estimator's downward bias, which made correctly encrypted
  AES-GCM tunnels report as unencrypted;
- a label-ordering mismatch between the plausibility mask and the classifier,
  which reported AES-CBC tunnels as 3DES *at 100% confidence* — a wrong answer
  delivered with maximum certainty, the worst failure mode an audit tool has;
- the one-directional modulo constraint that let 3DES shadow AES-CBC;
- linear score deduction flooring every bad capture at zero, erasing the
  difference between bad and catastrophic;
- a hand-assembled BPF filter that branched past the end of the program, which
  the kernel verifier rejected at attach time and which surfaced as total
  capture failure rather than as a filtering problem.

---

## Limitations

Stated plainly, because an audit tool that overstates its own certainty is worse
than none.

- **Exact ESP suite identification is impossible for framing-identical suites.**
  The tool reports the class and names the candidates.
- **Payload content is never recoverable.** No keys, no decryption, by design.
- **A hybrid key exchange is seen as a negotiation, not as an exchange.** The
  selection of an RFC 9370 additional key exchange is cleartext; the exchange
  is not. The tool cannot check that the ML-KEM step used the parameters that
  were negotiated, or that it succeeded, only that an `IKE_INTERMEDIATE`
  exchange followed. Hybrid dissection is validated against the lab generator,
  which is built from the RFC layouts; it has not been run against a capture
  from a real RFC 9370 implementation. `IKE_FOLLOWUP_KE`, used when rekeying,
  is recognised and counted but no rule reads it. Whether an RFC 8784 PPK was
  actually used is likewise decided inside the encrypted `IKE_AUTH`.
- **The baseline does not yet register the loss of a hybrid as a downgrade.**
  Drift is compared on classical strength. A link that goes from Curve25519
  with ML-KEM-768 to Curve25519 alone keeps its classical figure, so `watch`
  records it as steady. The single-capture finding (IKE-007) does fire.
- **Inference needs volume.** Under ~60 packets the length distribution is not
  stable and findings are marked provisional.
- **Throughput is measured, not claimed.** On a 146 MB capture, single-threaded:
  **115,000 packets/sec** for the full pipeline and **235,000 packets/sec** for
  the reader alone. That is the portable pure-Python path; the DPDK/C++
  ingestion path described in the proposal is a separate component and is not in
  this repository, so no line-rate claim is made. Rates depend on the host:
  reproduce them with `cipherguard bench`, which generates a 200,000-packet
  capture and reports the median of interleaved runs, model load excluded. The
  dashboard shows no packets/sec figure for captures under 10,000 packets,
  because a rate measured over a few milliseconds is noise.
- **Live capture is Linux-only** and needs `CAP_NET_RAW`. It degrades with an
  explanation rather than a traceback elsewhere.
- **The dashboard's own live-capture panel is a separate, simpler path** (a raw
  IPv4 socket, not the `sensor` command's `AF_PACKET` capture). It needs
  Administrator on Windows, sees only this host's traffic, ignores the interface
  selector, and has not been exercised against real IPsec traffic: its packet
  handling is tested with constructed datagrams. It has not been tried on
  Linux; use `sensor` there.
- **The IKE dissector is validated against five real captures**, and the
  **ESP inference model can now be validated against real tunnels using sidecar labels**
  (`cipherguard label-check` and `verify-real`). The public Wireshark corpus
  contains IKE handshakes without sustained ESP; endpoint ground truth supplied via
  `<capture>.label.json` closes that gap.
- **The default shipped model is trained synthetically for reproducible baseline accuracy.**
  When real tunnels are available, retrain with `cipherguard train --include-real <dir>`
  to evaluate with leave-one-capture-out validation and record exact corpus provenance
  in `meta.json`.
- **Vendor fingerprinting is best-effort.** Many gateways suppress vendor IDs;
  remediation then defaults to strongSwan syntax.
