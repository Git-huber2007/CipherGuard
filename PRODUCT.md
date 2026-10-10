# CipherGuard Product Specification: Analyst Dashboard

**Audience**: Network security analysts, cryptographic auditors, SOC engineers, and defense infrastructure operators.  
**Operational Environment**: Air-gapped enclaves, isolated security inspection networks, jumpboxes, and field workstations with zero outbound connectivity.

---

## 1. Executive Vision & Mission

CipherGuard is a passive, zero-trust cryptographic posture evaluation system for IPsec VPN tunnels (IKEv1, IKEv2, ESP) and 802.11 RF wireless networks. It operates entirely without private keys, certificates, pre-shared keys (PSKs), or payload decryption.

The CipherGuard dashboard is an **instrument panel for operational reality**. It exists to answer three immediate questions for a security analyst inspecting network traffic:
1. **What cryptographic algorithms and parameters are negotiated and in active use on our tunnels?**
2. **Where are our critical vulnerabilities, protocol downgrades, and post-quantum exposures?**
3. **What exact remediation configuration eliminates these risks across gateway hardware?**

The dashboard rejects simulated vanity metrics, synthetic vulnerability scores, and decorative marketing fluff. Every visual mark corresponds strictly to observed packet bytes, mathematical framing invariants (RFC 4303), or validated statistical inference.

---

## 2. Target Audience & Operational Reality

### 2.1 Operational Context
Analysts operating CipherGuard work under strict security constraints:
- **Zero Internet Access**: Enclaves are air-gapped or air-walled. No CDNs, no remote font endpoints (Google Fonts), no external analytics, no package repositories, and no telemetry services are reachable.
- **Strict Content Security Policy (CSP)**: Default policies forbid `unsafe-inline` scripts and external origins.
- **High-Stakes Decision Making**: Assessments dictate whether multi-gigabit perimeter tunnels or military tactical data links are safe, compromised, or subject to Harvest-Now-Decrypt-Later (HNDL) quantum threats.
- **Multi-Device Inspection**: Used across multi-monitor SOC workstations, field rugged laptops, and dim server room displays, requiring high contrast and flawless legibility.

### 2.2 Operational Modes
The dashboard operates interchangeably across two deployment topologies without architectural compromise:
1. **Live Sensor / API Server Mode** (`cipherguard serve` / `cipherguard sensor`):
   - Backed by local Python FastAPI service bound strictly to loopback (`127.0.0.1`) or an authenticated token-gated LAN interface (`CIPHERGUARD_TOKEN`).
   - Streams live wire sniffing events and live packet analyses over server-sent events (`/api/sniff/stream`).
2. **Static Portable Export Mode** (`cipherguard export-demo`):
   - Fully autonomous, zero-backend single-page application opened directly from disk (`file:///`) or static file servers.
   - Pre-computed scenario JSON files loaded locally without runtime degradation.

---

## 3. The Screen's Job (Core Jobs-to-be-Done)

The dashboard is structured around six essential analytical jobs:

### Job 1: Instant Posture & Weak-Link Triage
- **Primary Metrics**: Deliver a 0–100 Cryptographic Posture Score and Letter Grade (A–F) derived from NIST SP 800-77 and RFC 8247 compliance rules.
- **Worst-Link Spotlight**: Highlight the most vulnerable gateway pair immediately. In enterprise captures with multiple concurrent tunnels, analysts must instantly see which link exposes the organization.
- **Severity Ledger**: Break down findings by Critical, High, Medium, Low, and Informational tiers.

### Job 2: Wire Demarcation & Epistemic Attribution
- **Wire Framing Ribbon**: Provide a physical visual representation of the packet layout across the network boundary.
- **The Seam**: Delineate with absolute clarity where cleartext wire-parsed framing ends and encrypted, keyless inference begins.
- **Traceable Evidence**: For every inferred ESP cipher, expose the exact RFC 4303 block-size residue, ICV length, entropy distribution, and classifier confidence score.

### Job 3: Before-and-After Verification (Compare / Diff Mode)
- **Baseline vs. Hardened**: Ingest Capture A (legacy baseline) alongside Capture B (remediated tunnel) and render a side-by-side delta.
- **Verification Guarantee**: Show resolved findings (vulnerabilities extinguished), persisting findings (residual risks), and transform upgrade matrices side-by-side.

### Job 4: Post-Quantum Exposure & Harvest-Now-Decrypt-Later (HNDL)
- **Mosca Inequality Clock**: Real-time evaluation of $X + Y > Z$:
  - $X$ = Data Shelf-Life (years required for confidentiality, e.g., 5 to 30 years).
  - $Y$ = Migration Horizon (years required to deploy post-quantum cryptography).
  - $Z$ = Estimated time to a Cryptanalytically Relevant Quantum Computer (CRQC).
- **Migration Triage Queue**: Rank tunnels by post-quantum vulnerability (e.g., classical DH Group 2 or 14 vs. RFC 9370 ML-KEM-768 hybrid).

### Job 5: Actionable Remediation Synthesis & Gated Approval
- **Vendor Hardening Playbooks**: Generate exact, copy-paste-ready gateway configuration scripts for Cisco ASA/IOS, strongSwan, Fortinet FortiOS, and Juniper Junos.
- **Rollback Scripts**: Provide matched rollback configurations to ensure safe operational deployment.
- **Local Approval Gate**: Allow the analyst to digitally record administrative sign-off directly into the local SQLite store (`cipherguard-plans.db`) with an operator ID, preventing deployment of unapproved plans.

### Job 6: Local RF & Wi-Fi Posture Audit
- **Airspace Overview**: Enumerate all 802.11 APs, SSIDs, BSSIDs, signal strengths, security grades, and active association statuses.
- **Rogue Clone AP Detection**: Immediately flag identical SSIDs broadcasting on suspicious MACs or running downgraded security (e.g., WPA2 Enterprise clone downgraded to WPA2 Personal honeypot).
- **RF Spectrum Channel Utilization**: Render visual bell curves across 2.4 GHz and 5 GHz bands to identify co-channel congestion and rogue transmitters.

---

## 4. Trust & Truth Guarantees (The Epistemic Contract)

The dashboard adheres to strict engineering rules to maintain analyst trust:

| Principle | Operational Contract |
|---|---|
| **Zero Decryption** | CipherGuard never asks for, reads, stores, or processes private keys, pre-shared keys, or session keys. ESP payloads remain opaque ciphertext. |
| **Separation of Truth** | Cleartext observed headers and statistical inferences are segregated visually, semantically, and structurally across the entire interface. |
| **Zero Synthetic Vanity** | No "threat simulators", fake animations, canned hex inspectors, or artificial security dials. If data was not measured in the capture, render an em dash (`—`) or explicit "Not queried" status. |
| **Strict Privacy** | No outbound egress lookups unless the operator explicitly sets `CIPHERGUARD_EGRESS_LOOKUP=1`. With the flag off, the interface displays "Not queried". |
| **Traceable Provenance** | Display capture SHA-256 hashes, model weight fingerprints, and report digests directly on screen. |

---

## 5. Primary Analyst Workflows

```mermaid
flowchart LR
    A["Ingest: PCAP / Live Sniffer"] --> B["Triage: Posture Score & Ribbon"]
    B --> C["Deep Dive: Evidence & Rule Audit"]
    C --> D["Evaluate: PQC Harvest Clock"]
    D --> E["Action: Generate Hardening Config"]
    E --> F["Verify: Diff Baseline vs Hardened"]
```

1. **Intake & Triage**: Analyst loads pcap via drag-and-drop or CLI launch. Inspects the masthead status, top-level posture dial, and worst-link card within 5 seconds.
2. **Wire Dissection**: Analyst selects the wire ribbon. Verifies cleartext IKE parameters on the left (Teal) and inspects inferred ESP cipher suites on the right (Violet).
3. **Audit Group Review**: Analyst drills into grouped findings, filtering by Rule ID or Link. Clicks a finding to read the plain-English impact statement and RFC references.
4. **Hardening Generation**: Analyst navigates to Remediation, selects target hardware (e.g., `strongswan`), copies the synthesized `.conf` payload, and records analyst approval.
5. **Re-Test & Diff**: Following gateway reconfiguration, analyst runs `Compare Captures` to mathematically verify that all target findings were eliminated.
