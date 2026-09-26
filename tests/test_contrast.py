"""Text contrast, parsed from the stylesheet so it cannot quietly regress.

--faint used to be #8798a4: about 3:1 on white and 2.5:1 on the page paper,
which fails WCAG AA for body text and disappears entirely on a projector. Every
text token is now checked against every surface and tint token it can sit on,
in both themes, at 4.5:1.

The dark scheme also re-points the stylesheet's hard-coded colours through
generated --dk-* variables. Their text colours are checked against the lightest
tint the same block generates, which is the worst background they can meet.
"""

from __future__ import annotations

import os
import re

import pytest

CSS = os.path.join(os.path.dirname(__file__), "..", "cipherguard", "api", "static", "css",
                   "dashboard.css")

TEXT = ["ink", "muted", "faint", "observed", "inferred", "crit", "high", "med", "low", "info",
        "ok", "accent", "dim", "text-primary", "text-secondary", "text-muted", "text-brand",
        "text-success", "text-warning", "text-danger"]
SURFACES = ["surface", "sunk", "paper", "observed-bg", "inferred-bg", "accent-bg"]
AA = 4.5

pytestmark = pytest.mark.no_model


def _css() -> str:
    with open(CSS, encoding="utf-8") as fh:
        return fh.read()


def _luminance(hex_colour: str) -> float:
    h = hex_colour.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    def lin(v: float) -> float:
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)


def contrast(a: str, b: str) -> float:
    x, y = _luminance(a), _luminance(b)
    return (max(x, y) + 0.05) / (min(x, y) + 0.05)


def _tokens(block: str) -> dict[str, str]:
    return {k: v.lower() for k, v in re.findall(r"--([\w-]+)\s*:\s*(#[0-9a-fA-F]{3,6})\b", block)}


DARK = 'html[data-theme="dark"]{'


def _light_tokens(css: str) -> dict[str, str]:
    """Top-level :root blocks in source order; a later block overrides."""
    out: dict[str, str] = {}
    for block in re.findall(r"(?m)^:root\s*\{(.*?)\}", css, re.S):
        out.update(_tokens(block))
    return out


def _dark_block(css: str) -> str:
    """The dark theme's variable blocks (the tokens, then the generated --dk-*
    counterparts), joined. Dark is opt-in: it applies only under
    html[data-theme="dark"], which the theme switch sets."""
    blocks = []
    start = css.find(DARK)
    while start != -1:
        end = css.index("}", start)
        blocks.append(css[start + len(DARK): end])
        start = css.find(DARK, end)
    assert blocks, "no dark theme block"
    return "\n".join(blocks)


def test_dark_is_opt_in_not_forced_by_the_os():
    """A dark OS used to force the dark scheme with no way back. Light is the
    default now; the OS preference only counts when the reader picks System,
    and that is resolved in script, so the stylesheet must not follow it."""
    css = _css()
    assert "prefers-color-scheme" not in css
    assert css.count(DARK) == 2


def _dark_tokens(css: str) -> dict[str, str]:
    return {**_light_tokens(css), **_tokens(_dark_block(css))}


def test_contrast_helper_matches_known_values():
    assert contrast("#000000", "#ffffff") == pytest.approx(21.0)
    assert contrast("#8798a4", "#ffffff") == pytest.approx(2.98, abs=0.01)   # the old --faint


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_every_text_token_clears_aa_on_every_surface(scheme):
    css = _css()
    tokens = _light_tokens(css) if scheme == "light" else _dark_tokens(css)
    failures = [
        f"--{t} {tokens[t]} on --{s} {tokens[s]}: {contrast(tokens[t], tokens[s]):.2f}"
        for t in TEXT if t in tokens
        for s in SURFACES if s in tokens
        if contrast(tokens[t], tokens[s]) < AA
    ]
    assert not failures, "\n".join(failures)


def test_both_schemes_define_the_whole_palette():
    css = _css()
    dark = _tokens(_dark_block(css))
    missing = [t for t in TEXT + SURFACES if t not in dark]
    assert not missing, f"dark scheme falls back to light values for: {missing}"


def test_faint_is_readable_on_the_page_paper():
    """The token that started this: meta text on the grey page background."""
    tokens = _light_tokens(_css())
    assert contrast(tokens["faint"], tokens["paper"]) >= AA
    assert contrast(tokens["faint"], tokens["surface"]) >= AA


def test_generated_dark_counterparts_clear_aa():
    css = _css()
    block = _dark_block(css)
    gen = dict(re.findall(r"(--dk-[\w-]+)\s*:\s*(#[0-9a-fA-F]{6})\b", block))
    fg = {k: v for k, v in gen.items() if k.startswith("--dk-fg-")}
    bg = [v for k, v in gen.items() if k.startswith("--dk-bg-")]
    assert fg and bg
    worst_bg = max(bg + [_dark_tokens(css)["sunk"]], key=_luminance)
    failures = [f"{k} {v} on {worst_bg}: {contrast(v, worst_bg):.2f}"
                for k, v in fg.items() if contrast(v, worst_bg) < AA]
    assert not failures, "\n".join(failures)

    # every generated variable the stylesheet references is defined
    referenced = set(re.findall(r"var\((--dk-[\w-]+),", css))
    defined = set(re.findall(r"(--dk-[\w-]+)\s*:", block))
    assert referenced <= defined, sorted(referenced - defined)


def test_light_rendering_is_unchanged_by_the_dark_variables():
    """Each --dk-* reference carries the original colour as its fallback, and
    no --dk-* variable is defined outside the dark block."""
    css = _css()
    outside = re.sub(re.escape(DARK) + r"[^}]*\}", "", css)
    assert not re.search(r"(?m)^\s*--dk-[\w-]+\s*:", outside)
    for ref in re.findall(r"var\(--dk-[\w-]+,\s*([^)]*\)?)\)", css):
        assert re.match(r"(#[0-9a-fA-F]{3,6}|rgba\()", ref.strip()), ref
