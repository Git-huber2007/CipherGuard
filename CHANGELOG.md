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
- Every server-supplied value written into page markup goes through the
  escape helper, including numbers and grades that were interpolated as-is.
  A test renders a network and a capture named `<img src=x onerror=alert(1)>`
  and checks the name appears as text.

### Fixed

- The CBOM dialog showed a hard-coded inventory when the API was unreachable,
  and always in the static build. It now shows the capture's own CBOM or says
  none is available.
- The dashboard only worked when served on port 8000.
- Stand-in values (latency, channel, signal, band, authentication) are no
  longer displayed where nothing was measured.
- The shipped model is the one the documentation describes (default training
  settings), and the documented accuracy figures match what the commands print.
- A network name containing `&quot;` or `&lt;` no longer breaks its tooltip on
  the Wi-Fi spectrum chart.
- Printing with the shortcuts or CBOM dialog open no longer prints the dialog
  over the page.

### Changed

- Keyboard shortcuts need Alt.
- The exported report includes the IPsec findings and labels the bundled Wi-Fi
  example as an example.
- `launch_dashboard.bat` installs into a project `.venv` and no longer ends
  whatever process holds the port. `--port N` selects another port.
- The README is a short overview; the method is in `METHOD.md` and operation
  in `OPERATIONS.md`.
- The dashboard script is split into focused files under `js/`.
- Python is formatted with `ruff format`, checked in CI.
- Dashboard interface redesign according to `DESIGN.md` and `PRODUCT.md` specifications:
  - Unified color token system with 9-step teal-tinted neutral ramp, 3-tier text tokens, and zero raw hex literals.
  - Streamlined masthead into a single-row brand and tab header with quiet utility actions, paired with a dedicated controls toolbar.
  - Deboxed panel layout into open sections separated by 48px vertical rhythm and 1px hairline rules, eliminating borders, backgrounds, and radius on all sections.
  - Eliminated nested cards: in the Links panel, dropped borders on the detail pane and the Handshake/Tunnel boxes while preserving their teal/violet tints.
  - Redesigned Posture hero with strict hierarchy: heading first, followed by the 48px grade letter coloured by grade, 18px summary sentence, and 13px muted metadata with timestamp formatted as "9 Oct 2026, 17:37 UTC".
  - Replaced run-on severity chips with a single horizontal stacked distribution bar with segments sized by count, displaying counts and labels directly underneath.
  - Prominent full-width Wire Framing Ribbon lead with spacious 98px cells while preserving literal 13px (.8125rem) font floors.
  - Integrated capture upload into toolbar picker and empty state with drag-and-drop overlay.
  - Parity redesign applied across Wi-Fi posture and network inventory views.
  - Removed all border-left stripe callouts, inset-stripe box-shadows, and coloured glow shadows in favor of subtle semantic tints.
  - Removed `text-transform: uppercase` across 14 micro-label locations, establishing standard readable sentence/title casing.
  - Restricted `var(--mono)` strictly to wire values (addresses, SPIs, hex, suite names, kbd, code); switched stats and badges to IBM Plex Sans with `tabular-nums`.
  - Audited and deleted 75 redundant `!important` declarations, preserving only 14 structural and accessibility guarantees.
  - Refined motion system: spinner, toast, and modal entrances standardized to 150–200ms `ease-out` on `transform` and `opacity` only; reinforced universal `prefers-reduced-motion` reset.
  - Streamlined findings UX flow: removed duplicate findings from the selected link detail pane; established the Findings panel as the single unified list with link filtering controlled from the Links panel.
  - Grouped findings under collapsible severity headings (Critical, High, Medium, Low) with Critical open and lower tiers collapsed by default.
  - Dropped redundant per-row severity badges inside groups in favor of severity-bearing section headings.
  - Preserved By rule / By link segmented toggling, link filter clearing, and full keyboard/disclosure accessibility.
  - Minimalist UI component refinement according to `DESIGN.md`:
    - Replaced filled uppercase mono severity pills with an 8px coloured square and the word in sentence case, styled with IBM Plex Sans 13px (`var(--text-sm)`) and text in `--text-primary` (`var(--ink)`).
    - Applied the identical 8px square + sentence case + IBM Plex Sans 13px + `--text-primary` pattern to `"Observed"` and `"Inferred"` epistemic domain tags (`.domain-tag`, `.domain-tag.gl`), preserving touch targets (≥ 24px) for interactive glossary elements.
    - Updated server connection status pill (`.backend-status-pill`) to the 8px square + sentence case + 13px `--text-primary` pattern across online and offline states.
  - Conducted 16-configuration CDP visual design review (1440px / 390px, light / dark, across IPsec, Wi-Fi, Compare, and Live views), verifying zero horizontal overflow, 100% WCAG AA contrast (≥ 4.5:1), and minimum 24px interactive hit targets.
  - Baseline UI implementation according to `DESIGN.md`:
    - Standardized every control across the masthead and secondary toolbar to a uniform 36px height and `var(--radius-md)` (6px) corner radius, including `.backend-status-pill`, `.shortcuts-trigger-btn`, `.theme-pick select`, segmented switches (`.seg`, `.seg-btn`), and primary/secondary action buttons.
    - Styled native `<select>` controls with `appearance: none` and clean inline SVG chevrons styled for both light and dark modes with WCAG AA compliant contrast.
    - Relocated "Alt + A", "Alt + S", and "Alt + H" keyboard chips from button text into descriptive `title` tooltips and the accessible Shortcuts modal dialog (`#dialog-shortcuts`).
    - Implemented sticky section navigation (`.section-nav`) positioned cleanly beneath the pinned toolbar with active section tracking via `IntersectionObserver` and smooth jumping.
    - Aligned all masthead, toolbar, and section layout spacing to a strict 4px grid.
    - Universally enabled `font-variant-numeric: tabular-nums` across all data tables, stats grids, and counters.
  - Data visualization implementation according to `DESIGN.md`:
    - Replaced full-width divider-like violet confidence rule in ESP tunnels panel with a labelled meter: 4px track, violet fill (`var(--inferred)`), and percentage value on the right end in IBM Plex Sans with tabular numbers.
    - Applied the identical labelled meter component to Wi-Fi signal strength across the connection health card, grouped networks table, mesh AP cluster subtables, and flat BSSID table.
    - Audited and updated Posture Replay chart: added explicit Y-axis title ("Classical bits"), corrected X-axis title casing to sentence case ("Observation, in recorded order (not to time scale)"), and verified dark mode token contrast.
    - Audited and updated RF Spectrum channel-use visualizer: added explicit Y-axis ("Signal (dBm)") and X-axis ("Channel (band)") titles, eliminated sub-12px font sizes across power levels, channel numbers, UNII zone markers, and AP labels, increased viewBox height to 295px, and switched font stack to IBM Plex Sans with tabular numerals.
    - Audited post-quantum view: ensured tabular numerals on `.pqbits`, verified Mosca deadline and harvest clock status chips clear WCAG AA contrast across both light and dark themes.
- Stylesheet clean-up, with no change to how the page renders at 390, 768,
  1024 or 1440 px in either theme:
  - Rules for 38 classes nothing used are gone, and every selector outside a
    media query is now defined once.
  - Status tints, their borders and the text on them are named tokens
    (`--ok-bg`, `--warn-border`, `--danger-text`, ...) defined once in `:root`
    and once for dark. No hex colour is written anywhere else.
  - Breakpoints are 480, 768, 1024 and 1440 px. Rules that sat at 560, 640,
    780, 820, 880 and 900 px moved to the breakpoint below. The 360 px block
    was removed, so phones narrower than 361 px now get the 480 px layout.
  - `!important` remains only in the print sheet, on `[hidden]`, in the
    reduced-motion reset and in two places specificity cannot reach.
- Scripts no longer write `style` attributes. Fixed looks are classes,
  visibility is the `hidden` attribute, and computed values (meter widths,
  tooltip positions) reach the stylesheet as custom properties.
- The front-end rules above are enforced by `tests/test_frontend_lint.py`,
  which also fails when `docs/` is not the current build (`make demo`).

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
