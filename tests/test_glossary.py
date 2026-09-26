"""The plain-language layer: glossary tooltips and "why this matters".

Judges and decision-makers are not IPsec specialists. The glossary gives each
marked term a definition without jargon, reachable by hover, keyboard focus and
tap; every finding group carries one server-written sentence on why it matters.
"""

from __future__ import annotations

import json
import os
import re

import pytest

from tests.jsmodules import ESC, NODE, STATIC, dashboard_js, module, run_node

pytestmark = pytest.mark.no_model
needs_node = pytest.mark.skipif(NODE is None, reason="node not installed")

REQUIRED = {
    "ike": "IKE", "ike-sa-init": "IKE_SA_INIT", "ike-auth": "IKE_AUTH", "esp": "ESP",
    "spi": "SPI", "dh-group": "Diffie-Hellman group", "aead": "AEAD",
    "framing-class": "Framing class", "sweet32": "Sweet32", "mosca": "Mosca's inequality",
    "crqc": "CRQC", "cbom": "CBOM", "hndl": "Harvest now, decrypt later",
    "observed": "Observed", "inferred": "Inferred",
}
# vocabulary a definition may not lean on: the terms themselves, and protocol words
JARGON = ["IKE", "ESP", "SPI", "AEAD", "CRQC", "CBOM", "Sweet32", "Diffie-Hellman", "IPsec",
          "SA ", "PRF", "HMAC", "MODP", "nonce", "cipher suite", "transform"]


def _glossary() -> dict:
    with open(os.path.join(STATIC, "glossary.json"), encoding="utf-8") as fh:
        return json.load(fh)["terms"]


def test_glossary_covers_the_required_terms():
    terms = _glossary()
    for key, name in REQUIRED.items():
        assert key in terms, key
        assert terms[key]["term"] == name


def test_definitions_are_short_and_free_of_jargon():
    for key, entry in _glossary().items():
        d = entry["definition"]
        sentences = [s for s in re.split(r"(?<=[.!?])\s+", d.strip()) if s]
        assert 1 <= len(sentences) <= 2, (key, d)
        for word in JARGON:
            if word.strip().lower() == entry["term"].lower():
                continue
            assert word not in d, f"{key}: definition uses '{word.strip()}'"


def _keys_used() -> set[str]:
    html = open(os.path.join(STATIC, "index.html"), encoding="utf-8").read()
    js = dashboard_js()
    used = set(re.findall(r'data-gl="([\w-]+)"', html))
    used |= set(re.findall(r'Glossary\.term\("([\w-]+)"', js))
    table = module("Glossary", js)
    used |= set(re.findall(r'\[\s*"[^"]+",\s*"([\w-]+)"\s*\]', table))
    return used


def test_every_term_used_in_a_tooltip_exists_in_the_glossary():
    used = _keys_used()
    assert len(used) >= 12, used                       # the markers are really there
    missing = used - set(_glossary())
    assert not missing, f"tooltips reference terms with no definition: {sorted(missing)}"


def test_tooltips_are_not_hover_only():
    """Hover, keyboard focus and tap must each show the definition."""
    g = module("Glossary", dashboard_js())
    for event in ('"mouseover"', '"focusin"', '"click"', '"keydown"'):
        assert f"addEventListener({event}" in g, event
    assert 'tabindex="0"' in g and 'role="button"' in g and '"Escape"' in g
    css = open(os.path.join(STATIC, "css", "dashboard.css"), encoding="utf-8").read()
    assert re.search(r"\.gl\{[^}]*underline dotted", css)


@needs_node
def test_mark_labels_the_first_occurrence_only_and_never_part_of_a_word():
    got = run_node(ESC + "const document = undefined;\n" + module("Glossary") + r"""
      const html = Glossary.mark(esc(
        "IKEv2 uses IKE_SA_INIT then IKE; ESP tunnels, ESP again; SPIs vs SPI; "
        + "Mosca's inequality <b>not a tag</b>"));
      process.stdout.write(JSON.stringify({ html, url: Glossary.url }));
    """)
    html = got["html"]
    keys = re.findall(r'data-gl="([\w-]+)"', html)
    assert keys == ["ike-sa-init", "ike", "esp", "spi", "mosca"]
    assert "IKEv2" in html and 'data-gl="ike">IKE</span>v2' not in html
    assert html.count('data-gl="esp"') == 1                    # first occurrence only
    assert "&lt;b&gt;not a tag&lt;/b&gt;" in html              # input stays escaped
    assert got["url"] == "glossary.json"


def test_every_rule_has_a_plain_language_sentence():
    from cipherguard.audit.engine import rule_catalogue
    from cipherguard.audit.plain import WHY_IT_MATTERS

    for rule in rule_catalogue():
        why = WHY_IT_MATTERS.get(rule["id"])
        assert why, f"{rule['id']} has no why_it_matters sentence"
        assert why.endswith(".") and len(re.findall(r"[.!?](\s|$)", why)) == 1, why
        for word in JARGON:
            assert word not in why, f"{rule['id']}: '{word.strip()}' in '{why}'"


def test_finding_groups_carry_the_sentence():
    from cipherguard.audit.plain import WHY_IT_MATTERS
    from cipherguard.core.grouping import group_findings
    from cipherguard.core.models import Finding, Severity

    groups = group_findings([Finding("IKE-006", "t", Severity.HIGH, "a <-> b", "d", "r", "f"),
                             Finding("IKE-006", "t", Severity.HIGH, "c <-> d", "d", "r", "f")])
    assert groups[0]["why_it_matters"] == WHY_IT_MATTERS["IKE-006"]
    js = dashboard_js()
    assert "why_it_matters" in js and "Why this matters:" in js
