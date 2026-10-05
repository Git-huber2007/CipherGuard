# Changelog

Notable changes to CipherGuard. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- Without a token the server answers loopback host names only (`--allowed-host`
  adds others) and refuses state-changing requests from another web site.
- Content security policy and related headers on every response; the page uses
  no inline script.
- Lockout after repeated wrong tokens; per-client rate limit on the routes that
  analyse, write files or run operating-system commands.
- Request bodies are size-checked from `Content-Length`. Uploads are checked
  for a capture magic number and counted against a 4 GB directory ceiling. The
  per-file limit is now 500 MB.
- `/api/analyze` accepts only known rule IDs in `disabled`, and the report and
  audit log record which rules were switched off.
- Unreadable captures and malformed parameters return a 4xx with the reason
  instead of a 500. The interactive API docs are no longer served.

### Fixed

- The CBOM dialog showed a hard-coded inventory when the API was unreachable,
  and always in the static build. It now shows the capture's own CBOM or says
  none is available.
- The dashboard only worked when served on port 8000.
- Stand-in values (latency, channel, signal, band, authentication) are no
  longer displayed where nothing was measured.
- The shipped model is the one the documentation describes (default training
  settings), and the documented accuracy figures match what the commands print.

### Changed

- Keyboard shortcuts need Alt.
- The exported report includes the IPsec findings and labels the bundled Wi-Fi
  example as an example.
- `launch_dashboard.bat` installs into a project `.venv` and no longer ends
  whatever process holds the port. `--port N` selects another port.
- The README is a short overview; the method is in `METHOD.md` and operation
  in `OPERATIONS.md`.

## [1.0.0] - not yet tagged

First versioned state of the project.

### Analysis

- IKEv1 (Main, Aggressive, Quick Mode) and IKEv2 (`IKE_SA_INIT`, `IKE_AUTH`,
  `CREATE_CHILD_SA`) dissection from pcap and pcapng captures.
- ESP suite inference without decryption: a Random Forest and a NumPy 1D-CNN,
  constrained by the RFC 4303 framing mask.
- RFC 9370 additional key exchange transforms and the `IKE_INTERMEDIATE` and
  `IKE_FOLLOWUP_KE` exchanges, so a negotiated ML-KEM hybrid is recognised.
- Audit rules with a 0 to 100 posture score, mapped to NIST SP 800-77 Rev. 1
  and RFC 8247, with an external policy overlay.
- SQLite baseline per peer pair. `watch` exits with code 3 on a downgrade.
- Post-quantum exposure ranking from Mosca's inequality (`roadmap`).
- Wi-Fi audit from the operating system's own scan, including detection of a
  cloned SSID advertising weaker security.
- VPN tunnel, route redirect and DNS leak detection on the local host.

### Output

- CycloneDX 1.6 cryptographic bill of materials (`cbom`).
- Remediation plans with rollback for Cisco IOS, strongSwan, FortiOS and
  Junos, stored behind a maker-checker approval step.
- Dashboard that runs as a static site and against the live API, with compare
  mode, posture replay, a harvest clock, presentation mode and a glossary.
  Fonts are bundled so it works offline.

### Operation

- Continuous sensor mode on Linux with bounded evidence retention, a
  `healthcheck` command and a systemd unit.
- The API binds to loopback by default, refuses a non-loopback bind without a
  token, and allows cross-origin access only from configured origins.
- Dockerfile, Render blueprint and a Windows launcher.
- Lab capture generator, strongSwan interoperability lab, validation against
  public captures and against user-labelled captures.

### Project

- `python -m cipherguard` runs the CLI.
- The version is defined once, in `cipherguard/__init__.py`.
- Ruff lint configuration, pre-commit hooks, a CI workflow for pull requests,
  a pinned `requirements.lock` and Dependabot updates.

### Removed

- The radar display, terminal drawer, audio effects and simulated panels from
  earlier dashboard builds.
