# CipherGuard Design System: Visual & Interaction Architecture

**Context**: High-density analytical interface for network security analysts operating on isolated enclaves.  
**Implementation**: Vanilla HTML, CSS (`cipherguard/api/static/css/dashboard.css`), and JavaScript. Zero external CDNs or UI frameworks.

---

## 1. Design Philosophy: The Instrument Panel

CipherGuard is engineered as a **precision cryptographic instrument**, not an enterprise SaaS marketing dashboard. Every pixel exists to convey verified operational reality.

### Core Tenets
1. **Epistemic Honesty**: The interface visually segregates what was read directly from cleartext wire headers from what was mathematically inferred without keys.
2. **Dense, Non-Distracting Hierarchy**: Information density is maximized without visual noise. Surfaces are neutral and quiet; color is reserved strictly for semantic state and epistemic attribution.
3. **Guaranteed Contrast (WCAG AA 4.5:1)**: Every text token is verified to clear at least 4.5:1 contrast against every surface and tint it can rest upon in both light and dark themes.
4. **Resilience to Screen Variances**: Operates with pristine legibility across high-resolution Retina displays, low-contrast projectors, and dim tactical field monitors.

---

## 2. The Epistemic Color Rule: Parsed vs. Inferred

The foundational visual rule of CipherGuard is the strict color pairing between wire observations and cryptographic inferences:

| Domain | Semantic Meaning | Primary Token | Background Tint | Dark Primary | Dark Tint |
|---|---|---|---|---|---|
| **Observed (Parsed)** | Read directly from cleartext wire headers: IKE proposals, transforms, DH groups, SPIs, 802.11 beacon frames. | `--observed`<br>`#1b6e8c` | `--observed-bg`<br>`#e2eff4` | `--observed`<br>`#6cbcd8` | `--observed-bg`<br>`#12313c` |
| **Inferred (Deduced)** | Inferred from encrypted ESP payloads without keys using RFC 4303 framing residues, block sizes, and statistical classifiers. | `--inferred`<br>`#6d4e9c` | `--inferred-bg`<br>`#ece5f5` | `--inferred`<br>`#b9a2e6` | `--inferred-bg`<br>`#261f3b` |

### Architectural Invariants
- **Consistency**: This pairing is applied identically across the Wire Framing Ribbon (`.field.obs` vs `.field.inf`), Domain Tags (`.domain-tag.obs` vs `.domain-tag.inf`), Finding Badges, and Legend Swatches (`.swatch.obs` vs `.swatch.inf`).
- **Strict Distinction**: Violet is never used for parsed wire fields; Teal is never used for inferred cipher suites.
- **The Seam (`.seam`)**: The exact boundary between parsed cleartext and encrypted ciphertext is marked by a double vertical border (`border: 3px double var(--ink)`) and a centered label (`.seam-label`).

### 2.4 The Brand Mark: The Wire Ribbon Emblem

Rather than generic security tropes (shields, padlocks, keys), CipherGuard's brand identity is drawn directly from the **Wire Framing Ribbon**:
- **Geometry**: Hand-crafted SVG (`favicon.svg`) designed on a strict `16×16` coordinate grid (`viewBox="0 0 16 16"`).
- **Left Block (Teal `#1b6e8c`)**: `x=1..7` (`w=6`), representing cleartext wire parameters.
- **Center Bar (Dark Ink `#14212b`)**: `x=7..9` (`w=2`), representing the cryptographic key boundary seam.
- **Right Block (Violet `#6d4e9c` with `#d8c7f0` Hatching)**: `x=9..15` (`w=6`), representing ciphertext framing with crisp 45° diagonal hatch lines.
- **Production Asset Suite**:
  - `favicon.svg`: Vector icon scaling cleanly from 16px tab icon to 28px masthead mark with dark theme support (`@media (prefers-color-scheme: dark)`).
  - `favicon.ico`: Multi-resolution raster bitmap (16×16, 32×32, 48×48, 64×64).
  - `apple-touch-icon.png`: 180×180 iOS touch icon.
  - `icon-192.png` & `icon-512.png`: PWA manifest standard icons.
  - `og-image.png`: 1200×630 high-resolution social card featuring the 280px Wire Ribbon mark with dual epistemic accent rules.

---

## 3. Typographic System

The typeface family is **IBM Plex**, fully bundled and self-hosted under `cipherguard/api/static/fonts/` (SIL Open Font License). No external font CDNs are permitted.

```css
--sans: "IBM Plex Sans", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
--mono: "IBM Plex Mono", ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
```

### 3.1 Type Scale Tokens

All font sizes derive directly from the unified `:root` typographic scale:

| CSS Token | Rem Value | Pixel Equivalent | Role & Component Application |
|---|---|---|---|
| `--text-xs` | `0.75rem` | 12px | Timestamps, footnotes, micro-tags, metric subtitles, table secondary notes. |
| `--text-sm` | `0.8125rem` | 13px | **Core Analytical Floor**: Table cells, badges, button text, `.field .fname`, `.field .fval`, `.seam-label`. |
| `--text-base` | `0.9375rem` | 15px | Standard body copy, dropdown options, default UI copy. |
| `--text-md` | `1.0625rem` | 17px | Subsection titles, card headers, stat metric keys (`.stat .k`). |
| `--text-lg` | `1.25rem` | 20px | Section headers (`h2`), masthead brand title. |
| `--text-xl` | `1.625rem` | 26px | Hero subtitles, harvest clock values (`.hclock-value`). |
| `--text-2xl` | `2.125rem` | 34px | Primary posture score dial (`.score-num`). |

> [!IMPORTANT]
> **Literal 13px (.8125rem) Contract**:  
> `.field .fname`, `.field .fval`, and `.seam-label` must explicitly maintain `font-size: .8125rem`. Ribbon elements must never shrink below 13px at any viewport width.

### 3.2 Tabular Numerals
All quantitative readings—including timestamps, packet counts, IP addresses, SPI hex codes, clock countdowns, and scores—must utilize monospaced styling or tabular figures:
```css
font-variant-numeric: tabular-nums;
```

---

## 4. Spacing Scale & Spatial Architecture

The dashboard is structured around an editorial instrument layout where the page background is the pure surface color (`var(--surface)`).

### 4.1 Page Container & Sections
- **Page Canvas**: Surface color (`var(--surface)`) extends across the whole viewport.
- **Page Wrapper (`.wrap`)**: Max width `1180px`, centered, with `padding: 0 24px 72px`.
- **Open Sections (`.panel`)**: Sections lose box borders, backgrounds, and radii; they breathe as open architectural zones separated by **48px of vertical rhythm and a 1px hairline rule** (`border-bottom: 1px solid var(--rule)`).
- **Cards for Repeated Items Only**: Cards are strictly reserved for discrete repeated items: gateway link entries (`.link-item`, `.link-detail`), security findings (`.finding`), and access points/network tables (`.data-table`).
- **Two-Column Split (`.cols-2`)**: `grid-template-columns: 1fr 1fr` with 40px gap and row-level 48px hairline separation.

### 4.2 Geometric Corner Radii
Corner radii are strictly standardized:
- `--radius-sm` (`4px`): Chips, badges, small tags, text inputs, dropdowns.
- `--radius-md` (`6px`): Buttons, table rows, cards, ribbon boundary.
- `--radius-lg` (`10px`): Upload drop zone, modal dialog sheets.
- `--radius-full` (`9999px`): Status pills (`.backend-status-pill`), circular indicators.

---

## 5. Color Tokens & Dual Theme Architecture

Light is the default theme; Dark is opt-in via user selection (`html[data-theme="dark"]`). System preference is evaluated in JavaScript without forcing an unalterable dark theme.

### 5.1 Color Tokens Table

| Token Role | Light Theme (`:root`) | Dark Theme (`html[data-theme="dark"]`) | Description |
|---|---|---|---|
| `--surface` | `#ffffff` | `#152029` | Main page canvas and card surfaces |
| `--paper` | `#e9edf0` | `#0e161c` | Outer boundary and tool surfaces |
| `--sunk` | `#f3f6f8` | `#1b2731` | Recessed areas, stat boxes, code blocks |
| `--rule` | `#c3cfd8` | `#2f3f4b` | Structural dividers and hairline section rules |
| `--ink` | `#14212b` | `#e4ebf0` | High-contrast primary text |
| `--muted` | `#4b5a66` | `#b3c0ca` | Secondary descriptive text |
| `--faint` | `#596975` | `#98a7b3` | Low-priority metadata and borders |
| `--observed` | `#1b6e8c` | `#6cbcd8` | Cleartext wire-parsed elements |
| `--observed-bg`| `#e2eff4` | `#12313c` | Wire-parsed background tint |
| `--inferred` | `#6d4e9c` | `#b9a2e6` | Encrypted inference elements |
| `--inferred-bg`| `#ece5f5` | `#261f3b` | Inferred background tint |
| `--crit` | `#a81e13` | `#ff8f83` | Critical finding (F-grade, downgrade) |
| `--high` | `#a84b1d` | `#f2a56f` | High finding (weak DH, deprecated hash)|
| `--med` | `#7d630e` | `#dcc062` | Medium finding (non-AEAD, short key) |
| `--low` | `#3a6b8a` | `#8fbadb` | Low finding (advisory improvement) |
| `--info` | `#5b6872` | `#a6b3bd` | Informational audit note |
| `--ok` | `#1f6b4a` | `#71cf9f` | Strong / compliant security posture |

---

## 6. Allowed Component Catalogue

Only approved, purposeful components may be implemented:

### 6.1 Wire Framing Ribbon (`.ribbon`)
- **Placement**: Leads the IPsec assessment view full width as the very first section.
- **Fields (`.field.obs`, `.field.inf`)**: Equal-width spacious flex cells with generous padding (`22px 18px 24px`) and minimum height. Unbroken tokens (SPIs, vendor IDs) wrap via `overflow-wrap: anywhere;`. Never truncate SPIs.
- **The Seam (`.seam`, `.seam-label`)**: Delineates key boundary in normal document flow. `font-size: .8125rem` strictly preserved.

### 6.2 Sections & Stacks (`.panel`)
- Open architectural sections on the surface canvas without enclosing card frames or background pills.
- Separated by `padding-bottom: 48px; margin-bottom: 48px; border-bottom: 1px solid var(--rule);`.

### 6.3 Posture Score & Severity Distribution (`.scoreline`, `.score-num`, `.sev-bar-track`)
- **Grade Letter at 48px**: Crisp, tabular grade letter (`.score-num` at `3rem` / 48px, bold, colored by tier).
- **One Explanatory Sentence**: Concise plain-English operational status (`.score-sub`).
- **Single Horizontal Severity Bar**: Proportional segmented bar track showing critical, high, medium, and low distribution with precise counts. Circular dial SVG hidden.

### 6.4 Upload Zone (`.upload-zone`)
- Integrated into the toolbar capture picker (compact action button) and the no-capture empty state (prominent dashed drag-drop box). Automatically collapses when an assessment is active.

### 6.5 Finding Groups & Hierarchy (`.finding`, `.fhead`, `.fbody`, `.sev-group`)
- Accordion findings organized under severity headings (`Critical 11`, `High 7`, `Medium 12`, `Low 3`) with Critical open and lower tiers collapsed by default.
- Severity is borne by the section header; individual rows omit redundant per-row badges.
- Single unified findings list in Findings panel; selected links in Links panel set an interactive link filter with clearable filter banner.
- Includes concise, one-sentence plain-language explanation of impact and remediation.

### 6.6 Data Tables (`.data-table`, `table.net-table`)
- High-density tabular displays with explicit `th[scope="col"]`.
- Monospaced numeric alignment for channels, signal dBm, packet counts, and bit strengths.
- Distinct row states for active links and flagged rogue APs (`.rogue-ap-row`).

### 6.7 Backend Status Indicator (`.backend-status-pill`)
- Masthead quiet indicator conveying connection mode:
  - 8px coloured square (`.pulse-dot` with `border-radius: 1px`).
  - Word in sentence case (`"Server connected"` online, `"Saved assessments"` offline).
  - IBM Plex Sans 13px (`var(--text-sm)`), text in `--text-primary`.
  - Transparent background, subtle sunk hover state, no filled pill borders.
  - Normal operational state offline is never treated or styled as an error.

### 6.8 Modal Dialogs (`.modal-backdrop`, `.modal-sheet`)
- Accessible dialogs with `role="dialog"` and `aria-modal="true"`.
- Controlled via `ModalFocus` module: background inertness, Tab trapping, and focus restoration to opener on close.

### 6.9 Unified Button System (`.btn`)
- `.btn-primary`: Teal background (`var(--observed)`). Reserved for primary screen action (e.g., *Start Capture*, *Run Diff*).
- `.btn-secondary`: Subtle teal tint (`rgba(27, 110, 140, 0.08)`).
- `.btn-ghost`: Transparent background with border (`var(--rule)`).

### 6.10 Harvest Clock (`.hclock`)
- Flat instrument panel gauge displaying post-quantum shelf-life vs CRQC migration horizon.
- Zero decorative animation; tabular numerals with clear `.is-late` (`--crit`) or `.is-ok` (`--ok`) status badges.

### 6.11 Accessible Glossary (`.gloss`)
- Plain-English definitions loaded locally from `static/glossary.json`. Marked with a dotted underline and accessible on keyboard focus, hover, or tap.

### 6.12 Minimalist Severity & Epistemic Marks (`.sev-mark`, `.domain-tag`)
- Replaces heavy filled uppercase mono pills across the interface.
- Architecture:
  - 8px x 8px coloured square (`width: 8px; height: 8px; border-radius: 1px; flex: none; display: inline-block`).
  - Word in sentence case (e.g. `"Critical"`, `"High"`, `"Medium"`, `"Low"`, `"Observed"`, `"Inferred"`).
  - IBM Plex Sans 13px (`var(--sans)`, `var(--text-sm)` / 0.8125rem).
  - Text color in `--text-primary` (`var(--ink)`), never relying on color alone.
  - Transparent background and zero border padding.
  - Guaranteed $\ge 4.5:1$ contrast against surface background in both light and dark themes.
  - Preserved touch target compliance ($\ge 24\text{px}$) for interactive glossary-linked tags (`.domain-tag.gl`).

### 6.13 Baseline UI & Control Harmonization
- **Universal Control Height (36px)**: Every interactive control in the masthead and secondary toolbar conforms to a single uniform height:
  - Masthead: `.backend-status-pill`, `.shortcuts-trigger-btn`, `.theme-pick select` (36px).
  - Toolbar: Segmented switches (`.seg`, `.seg-btn`), capture dropdown (`#capture`), file upload button (`#upload-picker-trigger`), primary assessment CTA (`#run`), report export (`#ipsec-export-report`), and comparison selects (`#diff-capture-a`, `#diff-capture-b`, `#run-diff`) (36px).
- **Single Radius**: All controls share a single corner radius (`var(--radius-md)` / 6px).
- **Native Select Styling**: Native `<select>` elements use `appearance: none` with an inline SVG chevron encoded in CSS, with stroke colors calibrated for light (`#4b5a66`) and dark (`#b3c0ca`) themes to guarantee $\ge 4.5:1$ contrast.
- **Tooltip Keyboard Shortcuts**: Access chips ("Alt + A", "Alt + S", "Alt + H") are relocated from button label text into standard `title` tooltips and the accessible Shortcuts modal dialog (`#dialog-shortcuts`).
- **Sticky Section Navigation**: The multi-screen section navigation (`.section-nav`) stays sticky beneath the pinned masthead and toolbar (`top: 108px`), highlighting the active section in view via `IntersectionObserver` with an accessible `aria-current="true"` indicator and scroll margin offset (`168px`).
- **4px Spatial Grid**: All margins, paddings, and flex/grid gaps are harmonized to multiples of 4px.
- **Tabular Numerals**: Universal `font-variant-numeric: tabular-nums` applied across all metrics, stats dials, tables, and counters to eliminate horizontal jitter.

### 6.14 Labelled Meters & Data Visualization Standards (`.meter`, `.conf-meter`, `.signal-meter`)
- **Labelled Meter Architecture**:
  - Replaces solid full-width divider-like confidence bars with a labelled meter:
    - Text label on left (`.meter-label`, 13px Plex Sans, `--muted`).
    - 4px recessed track (`.meter-track`, `height: 4px; background: var(--sunk); border: 1px solid var(--rule); border-radius: 2px`).
    - High-contrast semantic fill (`.meter-fill`, violet `var(--inferred)` for ESP confidence; signal strength color `var(--ok)`/`var(--med)`/`var(--crit)` for Wi-Fi).
    - Right-aligned tabular value (`.meter-val`, Plex Sans 13px tabular-nums, `--ink`).
  - Unified across ESP tunnels confidence indicators, Wi-Fi health connection card, network tables (grouped & flat), and mesh AP cluster cards.
- **Data Visualization Chart Rules**:
  - **Explicit Axis Titles & Units**: Every quantitative axis bears a visible, semantic title and clear engineering units (e.g. "Classical bits", "Observation, in recorded order (not to time scale)", "Signal (dBm)", "Channel (2.4 GHz / 5 GHz band)").
  - **Sentence Case Casing**: Axis titles and legend descriptions adhere strictly to sentence case; no all-lowercase labels.
  - **Typographic Floor ($\ge 12\text{px}$)**: All axis ticks, power levels, channel numbers, UNII markers, and callout labels use `--text-xs` (12px / 0.75rem) or higher in IBM Plex Sans with tabular numerals. Sub-12px micro-text is prohibited.
  - **Dual Theme Contrast & Color Integrity**: Charts utilize semantic CSS variables (`--rule`, `--faint`, `--muted`, `--ok`, `--crit`, `--inferred`, `--observed`) ensuring $\ge 4.5:1$ contrast against light (`#ffffff`) and dark (`#152029`) backgrounds without hardcoded canvas colors.
---

## 7. Banned Patterns & Strict Anti-Patterns

To preserve clarity, integrity, and accessibility, the following design patterns are **strictly prohibited**:

```
❌ BANNED: Stripe Callouts & Diagonal Warning Bands
❌ BANNED: Uppercase Micro-Labels (< 12px)
❌ BANNED: Nested Cards (Box-in-Box Clutter)
❌ BANNED: Decorative Motion & Ambient Pulsing
```

### 7.1 Banned: Stripe Callouts
- **Prohibition**: No diagonal hazard stripes, candy-cane alert blocks, or zebra-patterned banners.
- **Rationale**: Striped textures introduce high-frequency visual vibration that distracts analysts from diagnosing real packet anomalies. Status must be conveyed through solid semantic borders, plain text, and severity chips.

### 7.2 Banned: Uppercase Micro-Labels
- **Prohibition**: No sub-12px (`< 0.75rem`) all-caps tracking soup.
- **Rationale**: Micro-labels drop below human acuity thresholds on projectors and high-DPI displays, failing WCAG readability standards. All metadata must adhere to the `--text-xs` (12px) or `--text-sm` (13px) floor with standard sentence or title casing.

### 7.3 Banned: Nested Cards
- **Prohibition**: No placing cards inside cards inside cards (`.panel > .card > .sub-card`).
- **Rationale**: Recursive card nesting creates padding starvation, clips critical columns, and clutters the visual hierarchy. Use flat surfaces (`--surface`), subtle sunken blocks (`--sunk`), or structured data tables.

### 7.4 Banned: Decorative Motion
- **Prohibition**: No bouncy hover effects, floating cards, glowing or pulsating rings, or looping SVG rotations.
- **Rationale**: Decorative motion induces cognitive fatigue in analysts monitoring real-time network streams and breaks WCAG vestibular motion standards. Transitions must be strictly functional (instant or $\le 150\text{ms}$ ease) and must respect `prefers-reduced-motion: reduce`.

---

## 8. Accessibility & Keyboard Navigation Standards

1. **Full Keyboard Accessibility**:
   - Roving `tabindex` across tab lists (Wi-Fi vs IPsec).
   - Dedicated keyboard shortcuts:
     - <kbd>Alt</kbd> + <kbd>S</kbd>: Rescan / Scan now
     - <kbd>Alt</kbd> + <kbd>E</kbd>: Open Evidence modal
     - <kbd>Alt</kbd> + <kbd>D</kbd>: Toggle Compare (Diff) mode
     - <kbd>Alt</kbd> + <kbd>K</kbd>: Open Keyboard Shortcuts help
     - <kbd>Esc</kbd>: Close active modal or exit Presentation Mode
2. **Focus Indicators**:
   - Universal high-visibility focus ring: `outline: 2px solid var(--observed); outline-offset: 2px;`.
3. **Screen Readers**:
   - Proper heading hierarchy (`h1` through `h3`).
   - Dynamic live status updates announced via `role="status"` and `aria-live="polite"`.
