"""Front-end rules that a linter would hold, written as tests.

There is no Node toolchain in this project (the dashboard is plain CSS and
classic scripts), so the rules a stylelint or eslint config would enforce live
here instead: where colours may be written, how many `!important`s are allowed,
that the stylesheet carries no dead or repeated selectors, which breakpoints
exist, and that the published copy under docs/ is the current front end.
"""

from __future__ import annotations

import glob
import os
import re
from collections import Counter
from collections.abc import Iterator

import pytest

from cipherguard.export.static_site import copy_assets

pytestmark = pytest.mark.no_model

ROOT = os.path.join(os.path.dirname(__file__), "..")
STATIC = os.path.join(ROOT, "cipherguard", "api", "static")
DOCS = os.path.join(ROOT, "docs")

TOKEN_BLOCKS = (":root", 'html[data-theme="dark"]')
BREAKPOINTS = {480, 768, 1024, 1440}
MAX_IMPORTANT = 10
HEX_COLOUR = r"(?<![&\w])#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})\b(?![\w-])"

# Class names the scripts assemble from data, so the literal never appears in
# the HTML or JS. Each entry names where it is built.
BUILT_IN_SCRIPT = {
    "cmp-same": "compare.js: cmp-${r.kind}",
    "cmp-stronger": "compare.js: cmp-${r.kind}",
    "cmp-weaker": "compare.js: cmp-${r.kind}",
    "is-fallback": "evidence.js: is-${n.kind}",
    "approved": 'hardening.js: "chip-status " + st.toLowerCase()',
    "staged": 'hardening.js: "chip-status " + st.toLowerCase()',
    "tone-med": "wifi.js: tone-${signalTone(...)}",
}


def _read(*parts: str) -> str:
    with open(os.path.join(STATIC, *parts), encoding="utf-8") as fh:
        return fh.read()


def _scripts() -> dict[str, str]:
    return {
        os.path.basename(p): _read("js", os.path.basename(p))
        for p in sorted(glob.glob(os.path.join(STATIC, "js", "*.js")))
    }


@pytest.fixture(scope="module")
def css() -> str:
    return re.sub(r"/\*.*?\*/", "", _read("css", "dashboard.css"), flags=re.S)


def _blocks(css: str) -> Iterator[tuple[str, str]]:
    """Each top-level `prelude { body }` of a stylesheet, in order."""
    i = 0
    while (j := css.find("{", i)) >= 0:
        depth, k = 1, j + 1
        while depth:
            depth += {"{": 1, "}": -1}.get(css[k], 0)
            k += 1
        yield css[i:j].rsplit(";", 1)[-1].strip(), css[j + 1 : k - 1]
        i = k


def _rules(css: str, at: str = "") -> Iterator[tuple[str, str, str]]:
    """(selector, declarations, enclosing at-rule) for every style rule."""
    for prelude, body in _blocks(css):
        if prelude.startswith(("@media", "@supports")):
            yield from _rules(body, prelude)
        elif not prelude.startswith("@"):
            yield " ".join(prelude.split()), body, at


def test_css_writes_colours_only_in_the_token_blocks(css):
    """A hex colour anywhere else is a tint that skips the dark theme. The old
    generated --dk-* variables are gone for the same reason."""
    assert "--dk-" not in css
    offenders = [sel for sel, body, _ in _rules(css) if sel not in TOKEN_BLOCKS and re.search(HEX_COLOUR, body)]
    offenders += [
        prelude for prelude, body in _blocks(css) if prelude.startswith("@keyframes") and re.search(HEX_COLOUR, body)
    ]
    assert not offenders, offenders


def test_scripts_write_no_colours():
    """Scripts choose a class or a token, never a colour. export-report.js is
    the exception: it writes a standalone document with its own stylesheet."""
    offenders = {
        name: re.findall(HEX_COLOUR, js)
        for name, js in _scripts().items()
        if name != "export-report.js" and re.search(HEX_COLOUR, js)
    }
    assert not offenders, offenders


def test_important_is_rare(css):
    """`!important` is for the two places specificity cannot reach: the print
    sheet, which must beat every screen rule, and [hidden]. Elsewhere it is
    counted, and the count may only go down."""
    counted = [
        sel
        for sel, body, at in _rules(css)
        if not at.startswith("@media print") and sel != "[hidden]"
        for _ in re.findall(r"!\s*important", body)
    ]
    assert len(counted) <= MAX_IMPORTANT, Counter(counted)


def test_every_css_class_is_used(css):
    """A class in the stylesheet that nothing in the HTML or JS mentions is
    dead weight; one that only a script assembles is listed above with its
    source, and that list is checked for stale entries too."""
    selectors = " ".join(re.sub(r"\[[^\]]*\]", "", sel) for sel, _, _ in _rules(css))
    classes = set(re.findall(r"\.(-?[A-Za-z_][\w-]*)", selectors))
    source = _read("index.html") + _read("404.html") + "".join(_scripts().values())
    mentioned = set(re.findall(r"[A-Za-z_][\w-]*", source))

    unused = classes - mentioned - set(BUILT_IN_SCRIPT)
    assert not unused, sorted(unused)
    stale = {c for c in BUILT_IN_SCRIPT if c not in classes or c in mentioned}
    assert not stale, sorted(stale)


def test_no_selector_is_defined_twice(css):
    """Outside media queries a selector has one rule, so there is one place to
    read and change it and no later copy silently overriding the first."""
    seen = Counter(", ".join(sorted(p.strip() for p in sel.split(","))) for sel, _, at in _rules(css) if not at)
    repeated = sorted(sel for sel, n in seen.items() if n > 1)
    assert not repeated, repeated


def test_only_the_agreed_breakpoints(css):
    widths = {
        int(w)
        for prelude, _ in _blocks(css)
        if prelude.startswith("@media")
        for w in re.findall(r"width\s*(?::|[<>]=?)\s*(\d+)px", prelude)
    }
    assert widths <= BREAKPOINTS, sorted(widths - BREAKPOINTS)


def test_served_licence_is_the_project_licence():
    """The footer links to a copy under static/ so it works offline and in the
    static build; it must be the LICENSE at the repository root."""
    with open(os.path.join(ROOT, "LICENSE"), "rb") as a, open(os.path.join(STATIC, "LICENSE.txt"), "rb") as b:
        assert a.read().replace(b"\r\n", b"\n") == b.read().replace(b"\r\n", b"\n")


def test_docs_copy_matches_the_live_front_end(tmp_path):
    """docs/ is the published static build. Its front-end files must be what
    `cipherguard export-demo --out docs` would write today; the analysis JSON
    under docs/data carries timestamps and is not compared."""
    copy_assets(str(tmp_path))
    drift = []
    for root, _, files in os.walk(tmp_path):
        for name in files:
            rel = os.path.relpath(os.path.join(root, name), tmp_path)
            published = os.path.join(DOCS, rel)
            if not os.path.isfile(published):
                drift.append(f"{rel} (missing)")
                continue
            with open(os.path.join(root, name), "rb") as a, open(published, "rb") as b:
                # line endings differ by the platform that ran the export
                if a.read().replace(b"\r\n", b"\n") != b.read().replace(b"\r\n", b"\n"):
                    drift.append(rel)
    assert not drift, f"run `make demo` to regenerate docs/: {sorted(drift)}"
