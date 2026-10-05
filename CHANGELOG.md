# Changelog

Notable changes to CipherGuard. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
