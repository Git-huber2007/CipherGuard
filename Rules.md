# AI Development Guidelines & Operational Boundaries — CipherGuard

**System:** CipherGuard (Defense & Cryptographic Assessment Framework)  
**Target Standard:** SIH26160 / NTRO Operational Standards  
**Document Version:** 1.0.0  

---

## 1. Purpose & Scope

This document defines the strict operational boundaries, engineering standards, and development rules for any AI agent or software engineer contributing to the **CipherGuard** codebase. All proposed code changes, refactors, and feature additions must comply with these guidelines.

---

## 2. Inviolable Core Constraints (Non-Negotiables)

1. **Zero-Decryption Invariant**:
   - **NEVER** write code that attempts to decrypt encrypted ESP or IKE payload bytes.
   - **NEVER** request, ingest, or store gateway private keys, pre-shared keys (PSKs), or session master keys.
   - All encrypted traffic assessment must rely strictly on metadata: wire length distributions, RFC 4303 modulo padding residues, SPI headers, and cleartext handshake proposals.

2. **Zero Payload Retention Invariant**:
   - **NEVER** persist packet payload bytes to disk, SQLite databases (`fleet.db`), or log outputs.
   - Only store extracted metadata: IP 5-tuples, SPI values, algorithm identifiers, DH group numbers, timing intervals, and computed scores.

3. **Mathematical Ground Truth Precedes Machine Learning**:
   - Probabilistic machine learning outputs (Random Forest / 1D-CNN) must **ALWAYS** be filtered and constrained by the deterministic RFC 4303 modulo arithmetic mask.
   - If an ML model predicts an algorithm that violates the mathematical padding residues observed on the wire, the deterministic mask must override the ML prediction.
   - Never report a probabilistic classification as a certainty.

4. **Epistemic Domain Separation**:
   - Preserve the strict two-domain model across all code, logs, and user interfaces:
     - **Observed Domain** (Teal: `#1b6e8c` / `#e2eff4`): Direct wire observations from cleartext headers.
     - **Inferred Domain** (Violet: `#6d4e9c` / `#ece5f5`): Deducible mathematical and statistical properties.
   - Never mix or conflate these domains in data models or UI presentations.

5. **100% Air-Gapped Autonomy**:
   - The system must function completely without internet access.
   - **NEVER** introduce outbound network calls, external analytics telemetry, phone-homes, or mandatory remote cloud dependencies.
   - The web interface must load gracefully using system fallback fonts (`ui-sans-serif`, `system-ui`) when external font CDNs are unreachable.

---

## 3. Technology Stack & Library Policies

### 3.1 Backend & Python Standards
- **Python Version**: Minimum Python 3.10+ required.
- **Dependency Philosophy**: Prefer Python standard library modules (`socket`, `struct`, `sqlite3`, `dataclasses`, `argparse`, `pathlib`) wherever possible.
- **Allowed Core Dependencies**:
  - `numpy>=1.24`: Fast numerical vector operations.
  - `scikit-learn>=1.3`: Supervised Random Forest classifiers.
  - `joblib>=1.3`: Model artifact loading.
- **Allowed Optional Dependencies**:
  - `fastapi`, `uvicorn`, `pydantic`: For `cipherguard serve` API mode only.
  - `pytest`, `httpx`: For automated testing only.
- **Prohibited Libraries**:
  - **NO** heavy deep learning runtimes (e.g., PyTorch, TensorFlow) without explicit architectural review.
  - **NO** Scapy or heavy external packet dissectors in the hot path. The internal binary stream dissector is optimized for zero-copy high throughput.

### 3.2 Frontend & Styling Standards
- **Vanilla CSS Only**:
  - All styling must be written in standard Vanilla CSS3 utilizing the established CSS custom properties in `docs/css/dashboard.css`.
  - **DO NOT introduce TailwindCSS**, Bootstrap, or external CSS component frameworks unless explicitly requested by the user.
- **Native Modern JavaScript**:
  - Pure ES2022+ Vanilla JavaScript.
  - **NO** heavy frontend frameworks (React, Angular, Vue) in the core distribution. The dashboard must run directly from raw files without compilation or bundler steps.
- **Web Audio API**:
  - All tactical sound effects must be synthesized procedurally in real-time via the browser's native `AudioContext`.
  - **DO NOT** bundle external audio files (.mp3, .wav) that bloat repository size.

---

## 4. Dual-Runtime Compatibility Invariant

CipherGuard supports two distinct operational frontend environments:
1. **Static GitHub Pages / Air-Gapped Mode** (`docs/`): Operates without any backend server. Reads static pre-generated scenario JSON files.
2. **Live Telemetry Server Mode** (`cipherguard/api/static/`): Communicates with the FastAPI backend over REST (`/api/v1/...`) and WebSocket streams.

**Rule**: Any changes made to the user interface, styling, or client-side scripts must be maintained across both environments. Never break static offline execution when adding dynamic API features.

---

## 5. Security & Operational Boundaries

1. **Network Binding Security**:
   - The API server (`cipherguard serve`) must bind to `127.0.0.1` by default.
   - If binding to public interfaces (`0.0.0.0`), the server must require and validate an administrative bearer token set via the `CIPHERGUARD_TOKEN` environment variable.
2. **Privilege Isolation & Sensor Safety**:
   - The live packet capture module (`cipherguard sensor`) requires `CAP_NET_RAW`.
   - Never instruct users to run the entire framework as `root`. Direct them to grant narrow capabilities via `setcap` on Linux.
   - The capture ring buffer must enforce strict retention boundaries (max 24 slices, max 4 GB aggregate disk spool) to prevent disk exhaustion attacks.
3. **Platform Resiliency**:
   - Native OS network inspection must degrade gracefully:
     - On Windows: Use `netsh wlan`.
     - On Linux: Use `iw` or `nmcli`.
     - If no wireless adapter exists, return an empty telemetry set with an informative status badge rather than throwing an unhandled exception.

---

## 6. Coding Conventions & Quality Assurance

- **Type Annotations**: All new Python functions and methods must include complete type annotations (`typing` module / PEP 585 & 604).
- **Docstrings & Comments**: Preserve existing docstrings. Document non-obvious mathematical algorithms (e.g., RFC 4303 padding modulo math, Mosca inequality calculations).
- **Error Handling**:
  - Never allow raw tracebacks to leak to end-user CLI outputs.
  - Handle corrupt or truncated PCAP files gracefully with actionable error messages and specific byte offsets.
- **Testing**:
  - Any new feature or dissector logic must include corresponding Pytest test cases in `tests/`.
  - The complete test suite (`python -m pytest tests/`) must pass before concluding any implementation task.
