# Project Memory & Active State Tracker (Memory.md) — CipherGuard

**System:** CipherGuard (AI-Powered Passive Network & RF Security Framework)  
**Problem Statement:** SIH26160 · National Technical Research Organisation (NTRO)  
**Active Workspace Root:** `c:\SIH-\final\cipherguard`  
**Last Updated:** 2026-09-23  

---

## 1. Project Context & Mission

CipherGuard audits the cryptographic posture of IPsec VPN deployments and ambient 802.11 RF wireless environments entirely from mirrored traffic and raw ambient spectrometry—**holding zero private keys, touching zero gateways, and modifying zero live configurations**.

### Inviolable Core Invariants
1. **Never Decrypt**: No private keys, PSKs, or gateway administrative credentials are ever required or accepted.
2. **Zero Payload Retention**: Cleartext packet payload bytes are never stored to disk or SQLite databases.
3. **Deterministic Precedence**: Mathematical RFC 4303 modulo padding residues must always strictly constrain and override probabilistic ML predictions.
4. **Epistemic Clarity**: Data is strictly segregated into **Observed** (Teal: `#1b6e8c`) and **Inferred** (Violet: `#6d4e9c`).
5. **Air-Gapped Autonomy**: Operates 100% offline with zero external cloud telemetry phone-homes.
6. **Dual Runtime Support**: UI and scripts must function both on static file hosting (GitHub Pages) and with the local live FastAPI telemetry server.

---

## 2. Active Documentation Suite

The complete 6-document AI context and governance system is active in `c:\SIH-\final\cipherguard\`:

- [PRD.md](file:///c:/SIH-/final/cipherguard/PRD.md): Product Requirements, User Personas, Functional & Non-Functional Requirements.
- [Architecture.md](file:///c:/SIH-/final/cipherguard/Architecture.md): System Data Flow, Epistemic Domain Model, Directory Layout, Tech Stack.
- [Rules.md](file:///c:/SIH-/final/cipherguard/Rules.md): AI Operational Boundaries, Coding Conventions, Security Invariants.
- [Phases.md](file:///c:/SIH-/final/cipherguard/Phases.md): Phased Milestone Roadmap (Phases 1–5 Complete, Phase 6 Upcoming).
- [Design.md](file:///c:/SIH-/final/cipherguard/Design.md): Visual Design Tokens, IBM Plex Typography, Tactical HUD & Audio Synthesizer.
- [Memory.md](file:///c:/SIH-/final/cipherguard/Memory.md): This dynamic session state and task tracking file.

---

## 3. Current Codebase State

### Modules & Capabilities
- **`cipherguard.dissector`**: Zero-copy libpcap/pcapng parser, IKEv1 (Main/Aggressive/Quick), IKEv2 (SA_INIT/AUTH/CREATE_CHILD), RFC 4303 ESP framing.
- **`cipherguard.ml`**: Modulo arithmetic mask, Random Forest & 1D-CNN estimators, SA feature extractor, model training and cross-validation CLI.
- **`cipherguard.audit`**: 0–100 posture scoring engine, NIST SP 800-77, NSA CNSA 2.0, RFC 8247 compliance rules.
- **`cipherguard.intel`**: SQLite baseline store (`fleet.db`), downgrade drift detector (Exit Code 3), Mosca's Theorem ($X + Y > Z$) PQC exposure calculator.
- **`cipherguard.wifi`**: Native OS WLAN interface (`netsh wlan` / Linux `iw`), 2.4/5/6 GHz spectrometry, Rogue AP and Evil Twin detector (MITRE T1557.001 / T1040).
- **`cipherguard.remediation`**: Vendor playbook generators (Cisco ASA, Fortinet FortiOS, strongSwan, Linux `iproute2`) with reverse rollback syntax.
- **`cipherguard.export`**: CycloneDX v1.6 CBOM JSON generator, air-gapped compliance dossier exporter.
- **`cipherguard.capture`**: Linux `AF_PACKET` raw socket bounded sniffer with ring buffer spool.
- **`cipherguard.lab`**: Reproducible synthetic scenario generator (`legacy`, `hardened`, `backbone`, `downgrade`).
- **`cipherguard.api` & `docs/`**: FastAPI backend server + static Single-Page Tactical HUD with 360° Polar RF Radar, Cyber Terminal drawer (`~`), and procedural Web Audio synthesizer.

### Automated Testing Baseline
- Test runner: `pytest tests/`
- Test count: ~151 tests covering dissection, ML inference, compliance scoring, downgrade detection, and API endpoints.

---

## 4. Recent Actions & Changes

- **2026-09-23**: Initialized and authored the complete 6-document AI and project governance specification suite:
  - Created `PRD.md` with comprehensive SIH26160 NTRO requirements.
  - Created `Architecture.md` with system diagrams, epistemic model, and subsystem deep-dives.
  - Created `Rules.md` establishing AI boundaries, coding standards, and security rules.
  - Created `Phases.md` documenting milestone status and Phase 6 planning.
  - Created `Design.md` documenting the tactical HUD design tokens, IBM Plex typography, and Web Audio specs.
  - Created `Memory.md` for cross-session state persistence.

---

## 5. Upcoming Tasks & Backlog (Phase 6)

1. **Distributed Sensor Mesh**:
   - Design mTLS edge telemetry push daemon for multi-site remote TAPs.
2. **eBPF Ingress Acceleration**:
   - Research and prototype Linux eBPF/XDP bypass for 100 Gbps optical transit links.
3. **PQC Extension Dissection**:
   - Add parsing for RFC 9370 post-quantum hybrid key exchange transforms (ML-KEM / ML-DSA).
4. **Autonomous Degradation Fuzzing**:
   - Implement simulated state-sponsored downgrade packet injection for SOC cyber drill training.
