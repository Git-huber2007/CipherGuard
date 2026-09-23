# Project Requirements Document (PRD) — CipherGuard

**Document Version:** 1.0.0  
**Project:** CipherGuard  
**Problem Statement:** SIH26160 · National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity (Smart India Hackathon 2026)  
**Status:** Approved / Active  

---

## 1. Executive Summary & Vision

**CipherGuard** is an AI-powered passive network protocol analyzer and sovereign security assessment framework. It provides deep cryptographic inspection of IPsec VPN deployments and real-time 802.11 RF wireless environments entirely from mirrored traffic and raw ambient spectrometry—**holding zero private keys, touching zero network gateways, and changing zero live configurations**.

Traditional cryptographic auditing relies on active administrative access to gateways, manual policy review, and credential sharing across siloed teams. This paradigm fails at scale: credentials leak, configurations drift unmonitored between audit windows, and blind spots proliferate across multi-vendor networks.

CipherGuard solves this problem by moving the inspection point from gateway management planes to the physical wire and RF spectrum:
1. It dissects cleartext IKEv1/IKEv2 session handshakes to extract negotiated security parameters.
2. It applies mathematical **RFC 4303 modulo arithmetic** alongside machine learning to infer encrypted ESP transform suites without decryption.
3. It passively monitors local 802.11 Wi-Fi frames to detect rogue access points, Evil Twins, and unencrypted honeypots targeting enterprise backhauls.
4. It maps cryptographic posture directly to sovereign standards (**NIST SP 800-77**, **NSA CNSA 2.0**, **MITRE ATT&CK**), evaluates Post-Quantum Cryptography (**PQC**) exposure via Mosca's Theorem, and outputs automated, multi-vendor remediation playbooks with rollback guarantees.

---

## 2. Target Users & Operational Personas

| Persona | Role | Primary Objective in CipherGuard |
|---|---|---|
| **Defense / Intelligence SOC Analyst** | Sovereign Security Operations (NTRO / CERT-In) | Monitor mirrored transit traffic for state-sponsored downgrade attacks, weak ciphers, and rogue perimeter RF devices in real time. |
| **Cryptographic Compliance Auditor** | Security & Compliance Auditor | Conduct periodic or continuous posture audits against NIST SP 800-77 and NSA CNSA 2.0; export signed CycloneDX CBOMs and print-ready dossiers. |
| **Enterprise Network Security Architect** | Infrastructure Operations & DevOps | Identify vulnerable peer-to-peer VPN tunnels and generate copy-paste hardening syntax for Cisco ASA, Fortinet FortiOS, and strongSwan gateways. |
| **Hackathon Evaluator / Research Judge** | SIH / Defense Technology Evaluator | Validate zero-decryption passive analysis claims, review deterministic accuracy vs. ML probabilistic outputs, and test downgrade detection. |

---

## 3. Core Problem Stated Precisely

An agency operating hundreds of IPsec gateways needs to identify which tunnels negotiate insecure or compromised cryptography. The conventional method requires logging into every router/firewall with privileged credentials. This introduces three major vulnerabilities:
1. **High Threat Surface**: Distributing administrative credentials across an audit team creates privilege escalation risks.
2. **Configuration Drift**: Gateways pass an annual audit but degrade unnoticed when operators apply temporary troubleshooting overrides.
3. **Decryption Impossibility**: Encrypted ESP traffic conceals its encryption algorithm. Standard analyzers cannot inspect ESP payloads without obtaining master encryption keys, which violates operational compartmentalization.

**CipherGuard's Solution**:
By tapping mirror ports (SPAN) and analyzing cleartext framing metadata, padding residues, and IKE negotiations, CipherGuard audits the entire fleet passively, continuously, and non-intrusively.

---

## 4. Functional Requirements (FR)

### 4.1 Ingress & Protocol Dissection
- **FR-1.1 (Multi-Format PCAP Ingress)**: Ingest libpcap and pcapng file formats containing IPv4/IPv6 traffic with streaming packet dissection.
- **FR-1.2 (IKEv1 Protocol Parsing)**: Dissect IKEv1 Main Mode, Aggressive Mode, and Quick Mode exchanges. Parse Security Association (SA), Proposal, Transform, Key Exchange (KE), Nonce, Identification (ID), and Vendor ID payloads.
- **FR-1.3 (IKEv2 Protocol Parsing)**: Dissect IKEv2 `IKE_SA_INIT`, `IKE_AUTH`, and `CREATE_CHILD_SA` packets. Extract Transform Types (Encryption, PRF, Integrity, Diffie-Hellman Group, Extended Sequence Numbers).
- **FR-1.4 (ESP Framing Dissection)**: Extract RFC 4303 encapsulation headers: SPI (Security Parameter Index), Sequence Number, and measure exact L4 packet lengths without inspecting or decrypting encrypted payloads.

### 4.2 Deterministic & AI-Powered Inference Engine
- **FR-2.1 (RFC 4303 Arithmetic Modulo Mask)**: Apply deterministic cipher block size constraints ($L_{\text{payload}} \pmod B$) to eliminate mathematically impossible cipher families (e.g., distinguishing 64-bit DES/3DES from 128-bit AES-CBC and stream/AEAD ciphers).
- **FR-2.2 (Hybrid ML Classifier)**: Implement a supervised machine learning inference pipeline (Random Forest / 1D-CNN) that estimates the probability distribution across candidate ESP transform suites based on packet length distributions, inter-arrival entropy, and directional flow metrics.
- **FR-2.3 (Ensemble Arbiter)**: Intersect ML predictions with the deterministic modulo mask such that mathematical ground truth strictly filters probabilistic ML outputs. Guarantee 100% framing-class classification accuracy.
- **FR-2.4 (Model Training & Validation Subsystem)**: Provide standalone CLI commands (`cipherguard train`, `cipherguard validate`) with cross-validation reporting and reproducible seed generation.

### 4.3 Wireless RF Spectrometry & Threat Detection
- **FR-3.1 (Native OS Wireless Ingress)**: Interface with native OS kernel wireless subsystems (Windows WLAN API via `netsh wlan` and Linux `iw`/`nmcli`) without third-party proprietary drivers.
- **FR-3.2 (Spectral Density Mapping)**: Passively aggregate RSSI, non-overlapping channels (2.4 GHz channels 1, 6, 11; 5 GHz UNII-1/2/3 bands; 6 GHz Wi-Fi 6E/7), beacon frames, and standard protocols (802.11a/b/g/n/ac/ax).
- **FR-3.3 (Rogue AP & Evil Twin Detector)**: Compute threat anomaly scores matching MITRE ATT&CK T1557.001 (Adversary-in-the-Middle) and T1040 (Network Sniffing) based on:
  - BSSID Organizationally Unique Identifier (OUI) mismatch against broadcasted vendor claims.
  - SSID cloning with abnormal signal attenuation delta ($>18$ dBm difference).
  - Open unencrypted honeypot networks mimicking enterprise ESSIDs.

### 4.4 Cryptographic Posture, Compliance & Threat Intel
- **FR-4.1 (Sovereign Scoring Engine)**: Grade session cryptographic posture on an objective 0–100 scale based on effective symmetric key strength, DH group bit security, hash collision resistance, and protocol version.
- **FR-4.2 (Standard Baseline Mapping)**: Benchmark assessed tunnels against:
  - **NIST SP 800-77 Rev. 1**: Guide to IPsec VPNs.
  - **NSA CNSA 2.0**: Commercial National Security Algorithm Suite requirements.
  - **RFC 8247 / RFC 9395**: Cryptographic Algorithm Implementation Requirements for IPsec.
- **FR-4.3 (Post-Quantum Mosca Theorem Calculator)**: Compute operational Store-Now-Decrypt-Later (SNDL) risk using Mosca's Inequality:
  $$X + Y > Z$$
  where $X$ = shelf-life of protected data, $Y$ = time required to migrate infrastructure to PQC, and $Z$ = time until a cryptanalytically relevant quantum computer (CRQC) emerges (baseline: year 2030 per CNSA 2.0).
- **FR-4.4 (Historical Baseline & Downgrade Watcher)**: Store peer-pair cryptographic profiles in an embedded SQLite database (`fleet.db`). Alert with exit code 3 upon detecting state-sponsored or misconfigured cipher downgrades (e.g., transition from 128-bit AES to 80-bit 3DES).

### 4.5 Remediation & Deliverables
- **FR-5.1 (Automated Multi-Vendor Playbooks)**: Generate turnkey, production-grade hardening configurations for:
  - Cisco ASA / Adaptive Security Appliance
  - Fortinet FortiOS
  - strongSwan Linux IPsec
  - Linux `iproute2` / XFRM
  - VyOS Universal Router
- **FR-5.2 (Reverse Rollback Playbooks)**: Automatically synthesize inverse rollback configurations for every generated playbook to guarantee zero operational lockouts.
- **FR-5.3 (Cryptographic Bill of Materials - CBOM)**: Export full cryptographic inventories in CycloneDX v1.6 JSON format for software supply-chain compliance.
- **FR-5.4 (Air-Gapped Compliance Dossier)**: Generate exportable, executive-grade JSON and print-formatted reports.

### 4.6 Presentation & Tactical Interface
- **FR-6.1 (Dual Deployment Modes)**:
  - **Static / Offline Dashboard**: Self-contained HTML/CSS/JS deployable to GitHub Pages or local air-gapped web roots without Python.
  - **Live Telemetry Server**: FastAPI backend delivering real-time streaming updates over WebSocket / HTTP endpoints (`http://127.0.0.1:8000`).
- **FR-6.2 (Tactical Operations HUD)**: Provide an interactive 360° Polar RF Radar scope, differential Before-vs-After capture comparison, interactive CLI drawer (`~`), and keyboard shortcut navigation.
- **FR-6.3 (Tactical Audio Synthesizer)**: Provide offline Web Audio synthesized radar sweeps, threat alerts, and verification chimes.

---

## 5. Non-Functional Requirements (NFR)

| ID | Category | Requirement Description |
|---|---|---|
| **NFR-1** | **Privacy & Inviolability** | **Zero Decryption & Zero Payload Retention**: Under no circumstances shall CipherGuard request, accept, or store private keys, nor shall it record packet payload contents to logs or persistent storage. |
| **NFR-2** | **Air-Gapped Autonomy** | The system must operate 100% offline with zero outbound network calls, telemetry telemetry phone-homes, or mandatory external CDN dependencies. System fonts gracefully fall back if Google Fonts are inaccessible. |
| **NFR-3** | **Performance & Latency** | Offline PCAP analysis must dissect and assess $>50,000$ packets per second on standard commercial hardware. The web dashboard must achieve first-paint rendering in $<200$ ms. |
| **NFR-4** | **Resource Bounds** | Live packet capture sensor (`cipherguard sensor`) must enforce strict bounded retention (default: max 24 time windows, 4 GB aggregate disk spool, 512 MB per slice). |
| **NFR-5** | **Platform Compatibility** | Core dissector, ML engine, and API server must support Windows 10/11, Ubuntu 22.04+ LTS, Debian 12, and macOS 13+. Live raw socket sniffing is Linux-specific (`AF_PACKET`). |
| **NFR-6** | **Security Posture** | The API server must bind by default to loopback `127.0.0.1`. Binding to `0.0.0.0` must be actively blocked unless a cryptographically strong `CIPHERGUARD_TOKEN` environment variable is defined. |

---

## 6. Success Metrics & Evaluator Verification

1. **Deterministic Accuracy**: 100% accuracy on framing-class classification across all standard test suites.
2. **Downgrade Detection**: Immediate alert triggering (exit code 3) when sequential captures demonstrate cryptographic degradation on the same tunnel endpoint pair.
3. **Execution Speed**: Full end-to-end assessment of enterprise PCAPs completed in under 5 seconds from CLI or Web UI.
4. **Reproducibility**: All sample captures generated on demand via `cipherguard lab` without requiring binary blob downloads.
