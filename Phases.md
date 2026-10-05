# Phased Implementation Roadmap — CipherGuard

**System:** CipherGuard (AI-Powered Passive Network & RF Security Framework)  
**Standard:** SIH26160 / NTRO Defense Roadmap  
**Document Version:** 1.0.0  

---

## 1. Overview of Development Lifecycle

The CipherGuard engineering roadmap is partitioned into six distinct, verifiable milestones. Each phase establishes a layer of capability, building from low-level binary wire dissection up to high-density tactical operations and distributed sensor telemetry.

```
[Phase 1] ───► [Phase 2] ───► [Phase 3] ───► [Phase 4] ───► [Phase 5] ───► [Phase 6]
 Dissection      Hybrid ML       Compliance     RF Spectrometry Tactical HUD    Distributed
 & Lab PCAPs     & RFC Mask      & Remediation   & Evil Twins    & Audio HUD    Sensor Mesh
 (COMPLETE)      (COMPLETE)      (COMPLETE)      (COMPLETE)      (COMPLETE)     (NEXT UP)
```

---

## 2. Phase Breakdown & Status Matrix

| Phase | Milestone Name | Primary Focus | Status | Test Coverage |
|---|---|---|---|---|
| **Phase 1** | Core Dissection & Synthetic Lab | High-throughput binary PCAP/IKE/ESP parsing | ✅ **Complete** | `tests/test_cipherguard.py`, `tests/test_fuzz.py`, `tests/test_realworld.py` |
| **Phase 2** | Hybrid ML & RFC Modulo Mask | Zero-decryption ESP suite inference | ✅ **Complete** | `tests/test_cipherguard.py`, `tests/test_evidence.py`, `tests/test_labels.py` |
| **Phase 3** | Compliance, PQC & Playbooks | NIST/CNSA scoring, Mosca PQC, Remediation | ✅ **Complete** | `tests/test_remediation.py`, `tests/test_review.py`, `tests/test_posture_replay.py`, `tests/test_harvest_clock.py` |
| **Phase 4** | 802.11 RF & Rogue AP Detection | Native OS WLAN audit & Evil Twin heuristics | ✅ **Complete** | `tests/test_wifi.py`, `tests/test_vpn.py` |
| **Phase 5** | Dashboard & Dual-Runtime UI | Static and live dashboard, compare mode, presentation mode | ✅ **Complete** | `tests/test_dashboard_features.py`, `tests/test_offline.py`, `tests/test_contrast.py`, `tests/test_glossary.py`, `tests/test_formatting.py` |
| **Phase 6** | Distributed Fleet Mesh & eBPF | Multi-node sensor sync & 100 Gbps eBPF probe | ⏳ **In progress** — hybrid post-quantum dissection (item 4) delivered; mesh, eBPF and threat simulation planned | `tests/test_pqc_hybrid.py` |

---

## 3. Detailed Milestone Specifications

### Phase 1: Core Dissection & Synthetic Wire Framing (Completed)
- **Goal**: Ingest mirrored packet traffic, reconstruct IKE state machines, and parse RFC 4303 ESP framing without external dependencies.
- **Key Deliverables**:
  - `cipherguard/dissector/pcap.py`: Streaming binary libpcap and pcapng file reader.
  - `cipherguard/dissector/ike.py`: One dissector for both versions. IKEv1 Main Mode, Aggressive Mode, Quick Mode, SA, Proposal, Transform, KE, Nonce, and Vendor ID payloads; IKEv2 `IKE_SA_INIT`, `IKE_AUTH`, and `CREATE_CHILD_SA` exchanges with Transform Types 1–5.
  - `cipherguard/dissector/esp.py`: Zero-decryption extraction of SPI, Sequence Numbers, and exact L4 framing boundaries.
  - `cipherguard/lab/pcapgen.py`: Synthetic generator producing reproducible test captures (`legacy.pcap`, `hardened.pcap`, `transitional.pcap`, `backbone.pcap`, `downgrade.pcap`).
- **Verification Gate**:
  - Dissect 10,000 packets in $<100$ ms.
  - Verified against five real-world public Wireshark PCAPs without parsing errors.

### Phase 2: Dual-Layer AI & Mathematical Inference Engine (Completed)
- **Goal**: Deduce encrypted ESP cryptographic algorithms from packet lengths and timing without private keys.
- **Key Deliverables**:
  - `cipherguard/core/framing.py` (the arithmetic) and `_mask_from_trace` in `cipherguard/ml/classifier.py` (the mask): Deterministic block-size modulo mask enforcing RFC 4303 padding constraints:
    $$L_{\text{encrypted}} = L_{\text{IV}} + L_{\text{plaintext}} + L_{\text{pad}} + 1 + 1 + L_{\text{ICV}}$$
  - `cipherguard/ml/features.py`: SA-level feature extraction (percentiles p10–p99, flow asymmetry, packet size variance).
  - `cipherguard/ml/classifier.py` (Random Forest and the inference engine) and `cipherguard/ml/cnn.py` (1D-CNN written directly on NumPy): Supervised classifiers.
  - `cipherguard/ml/validate.py`: Cross-model validation harness reporting exact-suite and framing-class accuracy.
  - CLI commands `cipherguard train` and `cipherguard validate`.
- **Verification Gate**:
  - **100% Framing-Class Accuracy** guaranteed by the mathematical mask.
  - Model weights serialize to about 3.7 MB in `models/` directory (`rf.joblib` 3.7 MB, `cnn.npz` 35 KB).

### Phase 3: Sovereign Compliance, Threat Intel & Remediation (Completed)
- **Goal**: Score tunnel configurations against sovereign standards, track downgrade drift, and generate turnkey remediation configs.
- **Key Deliverables**:
  - `cipherguard/audit/engine.py`: Objective 0–100 posture scoring engine.
  - `cipherguard/audit/policy.py` (the policy baseline) and `rule_catalogue()` in `cipherguard/audit/engine.py`: Rules mapping to NIST SP 800-77 Rev. 1 and NSA CNSA 2.0.
  - `cipherguard/intel/pqc.py`: Mosca's Theorem ($X + Y > Z$) calculator for Store-Now-Decrypt-Later (SNDL) quantum threat analysis.
  - `cipherguard/intel/baseline.py`: SQLite baseline repository (`BaselineStore`, for example `--db fleet.db`) tracking cryptographic drift across peer pairs with Exit Code 3 alerts on downgrades.
  - `cipherguard/remediation/`: Multi-vendor configuration generators for Cisco ASA, Fortinet FortiOS, strongSwan, and Linux `iproute2` with guaranteed reverse rollback playbooks.
  - `cipherguard/export/cbom.py`: CycloneDX v1.6 Cryptographic Bill of Materials JSON exporter.
- **Verification Gate**:
  - Verified detection of AES $\to$ 3DES downgrade scenario with immediate exit code 3.
  - Synthesized Cisco ASA and strongSwan configurations validated for syntax correctness.

### Phase 4: Real-Time 802.11 RF Spectrometry & Rogue AP Detection (Completed)
- **Goal**: Passively audit perimeter wireless environments for Evil Twins and rogue access points threatening IPsec transit backhauls.
- **Key Deliverables**:
  - `cipherguard/wifi/wlan_native.py`: Driverless native OS kernel interface (Windows `netsh wlan`, Linux `iw`/`nmcli`).
  - `cipherguard/wifi/auditor.py`: Real-time beacon analysis across 2.4 GHz, 5 GHz, and 6 GHz spectrum.
  - Anomaly scoring engine identifying:
    - BSSID OUI deviation from advertised manufacturer.
    - Signal strength divergence ($>18$ dBm delta on identical ESSIDs).
    - Unencrypted honeypots mimicking enterprise corporate networks.
  - MITRE ATT&CK mapping (T1557.001 / T1040).
- **Verification Gate**:
  - Passive discovery of local Wi-Fi networks in $<2$ seconds without third-party driver dependencies.

### Phase 5: Dashboard with Static and Live Execution (Completed)
- **Goal**: Provide an assessment dashboard that runs both as a static site and against the live API.
- **Key Deliverables**:
  - Single-page dashboard in `cipherguard/api/static/` (`index.html`, `css/dashboard.css`, `js/dashboard.js`), copied to `docs/` by `cipherguard export-demo`. The script is one file; there are no separate `app.js`, `radar.js`, `terminal.js` or `audio.js` modules.
  - The polar RF radar, the terminal drawer and the Web Audio effects built in this phase were later removed. Empty stubs remain in `dashboard.js`, and the Python CLI is the command interface.
  - Side-by-side Before-vs-After differential capture comparator.
  - Dual deployment support: Static GitHub Pages and FastAPI live backend (`http://127.0.0.1:8000`).
- **Verification Gate**:
  - Full test suite passing (421 tests; 407 passed and 14 skipped on the last local run, in about 4 minutes).
  - Standalone operation on GitHub Pages without backend requirements.

---

## 4. Phase 6: Distributed Fleet Mesh & Autonomous Sensors (Upcoming)

- **Objective**: Scale CipherGuard from single-node TAP inspection to a multi-probe distributed sensor fabric across nation-wide defense backbones.
- **Planned Work Items**:
  1. **Sensor Central Aggregator Daemon**:
     - Lightweight mTLS streaming protocol allowing distributed edge sensors (`cipherguard sensor`) to push streaming metadata to a central SOC instance.
  2. **eBPF Ingress Acceleration (Linux Kernel)**:
     - Implement an eBPF/XDP program to pre-filter UDP 500/4500 and IP protocol 50 directly in the kernel space, enabling passive analysis on 40 Gbps and 100 Gbps optical transit links.
  3. **Automated Continuous Threat Simulation**:
     - Embedded packet fuzzer and replay engine to test SOC readiness against simulated state-sponsored downgrade injections.
  4. **PQC Hybrid Post-Quantum Handshake Dissection** — ✅ **delivered** (the first Phase 6 item to land; the other three remain planned):
     - **Supported.** RFC 9370 Additional Key Exchange transform types 6–12 (ADDKE1–ADDKE7) are parsed and named from the key exchange registry, including ML-KEM-512/768/1024 (groups 35–37). The `IKE_INTERMEDIATE` (RFC 9242, type 43) and `IKE_FOLLOWUP_KE` (RFC 9370, type 44) exchanges are recognised and counted per session instead of being discarded. Code: `cipherguard/core/constants.py`, `cipherguard/dissector/ike.py`, `IkeSession.key_exchange()` in `cipherguard/core/models.py`.
     - **Audit.** IKE-007 ("No quantum-resistant key establishment") is withdrawn only when the responder-selected proposal contains a post-quantum group as the key exchange or as an additional key exchange, or the responder sends `USE_PPK`. A post-quantum exchange that was offered and not selected, or offered with no response observed, is not credited and the finding says so. IKE-014 (informational) reports an additional key exchange that was negotiated when no `IKE_INTERMEDIATE` was observed.
     - **Strength.** `cipherguard/core/strength.py` scores a hybrid at its strongest component against each adversary; the association is still bounded by its weakest other component. The roadmap (`intel/pqc.py`), the CBOM (`export/cbom.py`) and the dashboard follow the same figures.
     - **Lab.** `cipherguard lab` writes `pqc_hybrid.pcap` and `pqc_declined.pcap`, built from the RFC field layouts independently of the dissector. Tests: `tests/test_pqc_hybrid.py`.
     - **Limit.** The additional key exchange payloads are encrypted. Only the negotiated selection and the occurrence of the exchange are visible; the tool cannot confirm what the exchange carried or that it succeeded. It has been validated against the lab generator, not against a capture from a real RFC 9370 implementation.
     - **Not done.** ML-DSA (Dilithium) is an authentication method negotiated and used inside the encrypted `IKE_AUTH`, so there is nothing for a passive dissector to parse. The baseline store compares classical strength only, so losing a hybrid is not yet recorded as a downgrade by `watch`.
