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
| **Phase 1** | Core Dissection & Synthetic Lab | High-throughput binary PCAP/IKE/ESP parsing | ✅ **Complete** | 38 Tests |
| **Phase 2** | Hybrid ML & RFC Modulo Mask | Zero-decryption ESP suite inference | ✅ **Complete** | 24 Tests |
| **Phase 3** | Compliance, PQC & Playbooks | NIST/CNSA scoring, Mosca PQC, Remediation | ✅ **Complete** | 35 Tests |
| **Phase 4** | 802.11 RF & Rogue AP Detection | Native OS WLAN audit & Evil Twin heuristics | ✅ **Complete** | 22 Tests |
| **Phase 5** | Tactical HUD & Dual-Runtime UI | Polar radar, cyber terminal drawer, Web Audio | ✅ **Complete** | 32 Tests |
| **Phase 6** | Distributed Fleet Mesh & eBPF | Multi-node sensor sync & 100 Gbps eBPF probe | ⏳ **Planned** | In Design |

---

## 3. Detailed Milestone Specifications

### Phase 1: Core Dissection & Synthetic Wire Framing (Completed)
- **Goal**: Ingest mirrored packet traffic, reconstruct IKE state machines, and parse RFC 4303 ESP framing without external dependencies.
- **Key Deliverables**:
  - `cipherguard/dissector/pcap.py`: Streaming binary libpcap and pcapng file reader.
  - `cipherguard/dissector/ikev1.py`: Full parsing of IKEv1 Main Mode, Aggressive Mode, Quick Mode, SA, Proposal, Transform, KE, Nonce, and Vendor ID payloads.
  - `cipherguard/dissector/ikev2.py`: Parsing of `IKE_SA_INIT`, `IKE_AUTH`, and `CREATE_CHILD_SA` exchanges with Transform Types 1–5.
  - `cipherguard/dissector/esp.py`: Zero-decryption extraction of SPI, Sequence Numbers, and exact L4 framing boundaries.
  - `cipherguard/lab/generator.py`: Synthetic generator producing reproducible test captures (`legacy.pcap`, `hardened.pcap`, `backbone.pcap`, `downgrade.pcap`).
- **Verification Gate**:
  - Dissect 10,000 packets in $<100$ ms.
  - Verified against five real-world public Wireshark PCAPs without parsing errors.

### Phase 2: Dual-Layer AI & Mathematical Inference Engine (Completed)
- **Goal**: Deduce encrypted ESP cryptographic algorithms from packet lengths and timing without private keys.
- **Key Deliverables**:
  - `cipherguard/ml/rfc_mask.py`: Deterministic block-size modulo mask enforcing RFC 4303 padding constraints:
    $$L_{\text{encrypted}} = L_{\text{IV}} + L_{\text{plaintext}} + L_{\text{pad}} + 1 + 1 + L_{\text{ICV}}$$
  - `cipherguard/ml/features.py`: SA-level feature extraction (percentiles p10–p99, flow asymmetry, packet size variance).
  - `cipherguard/ml/model.py`: Supervised Random Forest and 1D-CNN classifiers.
  - `cipherguard/ml/evaluate.py`: Cross-validation harness reporting exact-suite and framing-class accuracy.
  - CLI commands `cipherguard train` and `cipherguard validate`.
- **Verification Gate**:
  - **100% Framing-Class Accuracy** guaranteed by the mathematical mask.
  - Model weights serialize to $<2$ MB in `models/` directory.

### Phase 3: Sovereign Compliance, Threat Intel & Remediation (Completed)
- **Goal**: Score tunnel configurations against sovereign standards, track downgrade drift, and generate turnkey remediation configs.
- **Key Deliverables**:
  - `cipherguard/audit/engine.py`: Objective 0–100 posture scoring engine.
  - `cipherguard/audit/rules.py`: Rules mapping to NIST SP 800-77 Rev. 1 and NSA CNSA 2.0.
  - `cipherguard/intel/pqc.py`: Mosca's Theorem ($X + Y > Z$) calculator for Store-Now-Decrypt-Later (SNDL) quantum threat analysis.
  - `cipherguard/intel/store.py` & `downgrade.py`: SQLite baseline repository (`fleet.db`) tracking cryptographic drift across peer pairs with Exit Code 3 alerts on downgrades.
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

### Phase 5: High-Density Tactical Dashboard & Operations HUD (Completed)
- **Goal**: Provide a mission-ready, cyber defense operations dashboard with dual static and live execution.
- **Key Deliverables**:
  - Single-Page Tactical HUD (`docs/index.html`, `dashboard.css`, `app.js`).
  - `radar.js`: Polar 360° RF radar canvas with real-time radial AP rendering and threat crosshair locks.
  - `terminal.js`: Embedded cyber terminal drawer triggered by <kbd>~</kbd> / <kbd>`</kbd> supporting tactical CLI commands.
  - `audio.js`: Zero-asset procedural Web Audio synthesizer delivering tactile radar pings and threat klaxons.
  - Side-by-side Before-vs-After differential capture comparator.
  - Dual deployment support: Static GitHub Pages and FastAPI live backend (`http://127.0.0.1:8000`).
- **Verification Gate**:
  - Full test suite passing (151 tests in $<50$ seconds).
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
  4. **PQC Hybrid Post-Quantum Handshake Dissection**:
     - Dissect emerging post-quantum IKEv2 extensions (RFC 9370 / RFC 9242) including ML-KEM (Kyber) and ML-DSA (Dilithium) transform proposals.
