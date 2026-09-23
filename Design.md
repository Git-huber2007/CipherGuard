# UI/UX & Visual Design System (Design.md) — CipherGuard

**System:** CipherGuard (Tactical Cyber Defense & Wireless Assessment Framework)  
**Standard:** SIH26160 / NTRO Human Factors & Operational Ergonomics  
**Document Version:** 1.0.0  

---

## 1. Design Philosophy & Tactical Ethos

CipherGuard is engineered for defense-sector SOC analysts, cryptographic auditors, and electronic warfare evaluators. The interface departs from decorative SaaS consumer aesthetics in favor of a **high-density, tactical operations HUD** built on three foundational principles:

1. **Epistemic Color Semantics**: Color carries epistemological meaning rather than aesthetic decoration. An analyst must intuitively perceive the boundary between cleartext-measured fact and statistical inference without reading explanatory footnotes.
2. **Glanceable Telemetry Density**: Maximize above-the-fold information density. Metrics, findings, RF spectrum, and session states are visible simultaneously with minimum scrolling.
3. **Tactile & Auditory Responsiveness**: Instant keyboard navigation, micro-animations, and offline Web Audio acoustic feedback reinforce operational command and situational awareness.

---

## 2. Epistemological Color System

The core visual language relies on a dedicated two-color epistemological pairing applied consistently across wire ribbons, panel borders, data tags, and finding badges:

```
+-------------------------------------------------------------------------------+
|                        EPISTEMIC CHROMATIC CODING                             |
+------------------------------------+------------------------------------------+
|      OBSERVED DOMAIN (Teal)        |         INFERRED DOMAIN (Violet)         |
|  --observed:    #1b6e8c            |  --inferred:    #6d4e9c                  |
|  --observed-bg: #e2eff4            |  --inferred-bg: #ece5f5                  |
+------------------------------------+------------------------------------------+
| Applied to:                        | Applied to:                              |
| - Cleartext IKE negotiation headers| - ESP encrypted algorithm inference      |
| - Unencrypted Wi-Fi beacon frames  | - RFC 4303 padding modulo residues       |
| - Measured packet byte counts      | - Inter-arrival entropy metrics          |
| - Explicit DH Groups & SPIs        | - Machine learning probability rankings  |
+------------------------------------+------------------------------------------+
```

### Complete Color Token Reference

```css
:root {
  /* --- Epistemic Color Tokens --- */
  --observed:     #1b6e8c;  /* Deep Analytical Teal */
  --observed-bg:  #e2eff4;  /* Muted Teal Tint */
  --inferred:     #6d4e9c;  /* Sovereign Royal Violet */
  --inferred-bg:  #ece5f5;  /* Muted Violet Tint */

  /* --- Severity & Finding Hierarchy --- */
  --crit:         #a81e13;  /* Critical Red (Immediate Exploit / Broken Cryptography) */
  --high:         #c05621;  /* High Orange (Legacy Cipher / Deprecated DH Group) */
  --med:          #8a6d0f;  /* Medium Amber (SNDL Exposure / Missing PFS) */
  --low:          #3a6b8a;  /* Low Steel Blue (Minor Protocol Deviations) */
  --info:         #6b7a86;  /* Neutral Slate (Informational Metadata) */
  --ok:           #1f6b4a;  /* Verified Forest Green (NSA CNSA 2.0 Compliant) */

  /* --- Base Surfaces & Neutrals --- */
  --paper:        #e9edf0;  /* Cool Tactical Foundation / Canvas Background */
  --surface:      #ffffff;  /* Primary Card & Elevated Panel Surface */
  --sunk:         #f3f6f8;  /* Recessed Metric Trays & Data Insets */
  --ink:          #14212b;  /* Deep Carbon Text & Primary Glyph Ink */
  --muted:        #5a6b78;  /* Subdued Secondary Label Text */
  --faint:        #8798a4;  /* De-emphasized Metadata & Timestamps */
  --rule:         #c3cfd8;  /* Crisp Hairline Borders & Structural Dividers */

  /* --- Semantic Text Helpers --- */
  --text-primary:   #14212b;
  --text-secondary: #475569;
  --text-muted:     #64748b;
  --text-brand:     #1b6e8c;
  --text-success:   #15803d;
  --text-danger:    #b91c1c;
}
```

---

## 3. Typography & Hierarchy

The interface utilizes **IBM Plex**—an open, engineered grotesque type system designed for technical clarity:

- **Primary Analytical Body (`--sans`)**: `"IBM Plex Sans"`, `ui-sans-serif`, `system-ui`, `-apple-system`, `"Segoe UI"`, `sans-serif`.
- **Cryptographic Monospace (`--mono`)**: `"IBM Plex Mono"`, `ui-monospace`, `"SFMono-Regular"`, `Menlo`, `Consolas`, `monospace`. Applied to hex SPIs, packet offsets, MAC/BSSIDs, code snippets, and the interactive terminal drawer.

### Unified Typographic Scale

| Token | Rem | Px Value | Primary Usage |
|---|---|---|---|
| `--text-xs` | `0.75rem` | 12px | Footnotes, RFC citations, timestamp micro-tags, BSSID chips |
| `--text-sm` | `0.8125rem` | 13px | Table cells, badge labels, secondary metadata, terminal output |
| `--text-base` | `0.9375rem` | 15px | Default interface body text, modal copy, narrative summaries |
| `--text-md` | `1.0625rem` | 17px | Subheadings, card titles, parameter labels |
| `--text-lg` | `1.25rem` | 20px | Major section headings (H2), panel mastheads |
| `--text-xl` | `1.625rem` | 26px | Hero banner titles, primary score dials, modal headers |
| `--text-2xl` | `2.125rem` | 34px | Large KPI numerical readouts (0–100 score, packet counters) |

---

## 4. Geometric & Spatial System

```css
:root {
  /* Corner Radii */
  --radius-sm:    4px;      /* Inline badges, small tags, text inputs */
  --radius-md:    6px;      /* Action buttons, table cards, dialog containers */
  --radius-lg:    10px;     /* Major HUD panels, hero cards, terminal drawer */
  --radius-full:  9999px;   /* Status pills, indicator dots, radar blips */

  /* Shadows & Depth */
  --shadow-sm:    0 1px 2px rgba(20, 33, 43, 0.05);
  --shadow-md:    0 4px 6px -1px rgba(20, 33, 43, 0.08), 0 2px 4px -1px rgba(20, 33, 43, 0.04);
  --shadow-hud:   0 10px 15px -3px rgba(20, 33, 43, 0.1), 0 4px 6px -2px rgba(20, 33, 43, 0.05);
  --shadow-glow:  0 0 12px rgba(27, 110, 140, 0.35);
}
```

---

## 5. Tactical UI Components

### 5.1 Protocol Wire Ribbon
A horizontal streaming bar at the top of session cards. Each packet is rendered as a distinct segment:
- Teal blocks represent cleartext IKE framing.
- Violet blocks represent encrypted ESP frames.
- Segment width is proportional to packet byte length.
- Hovering displays exact packet offset, SPI, sequence number, and measured RFC 4303 padding residue.

### 5.2 Tactical 360° Polar RF Radar Scope (`radar.js`)
An HTML5 Canvas element rendering a polar coordinate map of ambient 802.11 beacons:
- **Center**: Local host NIC $(0,0)$.
- **Radius**: Radial distance mapped inversely to RSSI ($-30$ dBm near the center, $-90$ dBm near the perimeter ring).
- **Angle**: Distributed by channel frequency (2.4 GHz in the upper quadrant, 5 GHz in the lower quadrants).
- **Threat Indicator**: Rogue APs and detected Evil Twins are encircled in a pulsating crimson crosshair with target tracking coordinates.

### 5.3 Interactive Cyber Terminal Drawer (`terminal.js`)
A drop-down command terminal toggled via <kbd>~</kbd> or <kbd>`</kbd>:
- Background: `#14212b` (Deep Carbon).
- Font: `"IBM Plex Mono"` in emerald green (`#38bdf8` / `#22c55e`).
- Supported Commands:
  - `scan`: Trigger local Wi-Fi audit.
  - `audit <file>`: Execute live assessment on PCAP.
  - `diff <a.pcap> <b.pcap>`: Run comparative posture delta.
  - `remediate <vendor>`: Generate hardening playbook (cisco, fortinet, strongswan).
  - `pqc`: Display Mosca's inequality and Q-Day countdown.
  - `dossier`: Generate exportable compliance summary.

### 5.4 Procedural Web Audio Sound Synthesizer (`audio.js`)
Zero-footprint sound generation utilizing native browser Web Audio API oscillator nodes:
- **Radar Ping**: Sine wave at 880 Hz decaying over 120 ms.
- **Threat Klaxon (Evil Twin Detected)**: Dual-tone square wave alternating between 220 Hz and 440 Hz.
- **Compliance Chime**: Harmonic tri-chord (C5-E5-G5) on clean posture validation.

---

## 6. Keyboard Shortcut Taxonomy

| Keybinding | Scope | Function |
|---|---|---|
| <kbd>?</kbd> / <kbd>H</kbd> | Global | Open Keyboard Shortcuts Cheat Sheet modal |
| <kbd>~</kbd> / <kbd>`</kbd> | Global | Toggle Interactive Cyber Terminal Drawer |
| <kbd>1</kbd> / <kbd>W</kbd> | Global | Switch to Wi-Fi RF Spectrometry & Radar tab |
| <kbd>2</kbd> / <kbd>I</kbd> | Global | Switch to IPsec Protocol Analysis tab |
| <kbd>Alt</kbd> + <kbd>A</kbd> | IPsec | Execute immediate PCAP assessment |
| <kbd>Alt</kbd> + <kbd>S</kbd> | Wi-Fi | Trigger immediate RF wireless re-scan |
| <kbd>Esc</kbd> | Global | Close active modal, drawer, or help HUD |
