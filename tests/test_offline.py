"""The dashboard works with no internet connection.

It is meant for isolated analyst networks and for a static export opened from
disk, so nothing it needs may come from another domain. IBM Plex is bundled
under static/fonts with its licence, declared with @font-face, packaged, and
exported.
"""

from __future__ import annotations

import fnmatch
import os
import re
import tomllib

import pytest

from tests.jsmodules import STATIC

pytestmark = pytest.mark.no_model

ROOT = os.path.dirname(STATIC.rstrip(os.sep).rsplit(os.sep, 2)[0])
LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def _read(*parts: str) -> str:
    with open(os.path.join(STATIC, *parts), encoding="utf-8") as fh:
        return fh.read()


def _hosts(text: str) -> set[str]:
    return {h.lower() for h in re.findall(r"(?:https?:)?//([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|\d+\.\d+\.\d+\.\d+|localhost)", text)}


@pytest.mark.parametrize("page", ["index.html", "404.html"])
def test_pages_reference_no_external_domain(page):
    external = _hosts(_read(page)) - LOOPBACK
    assert not external, f"{page} reaches out to {sorted(external)}"


def test_stylesheet_fetches_nothing_remote():
    css = _read("css", "dashboard.css")
    assert "@import" not in css
    assert not re.search(r"url\(\s*['\"]?(https?:)?//", css)


def test_fonts_are_bundled_declared_and_licensed():
    css = _read("css", "dashboard.css")
    faces = re.findall(r"@font-face\{(.*?)\}", css, re.S)
    declared = {(re.search(r'font-family:"([^"]+)"', f).group(1),
                 int(re.search(r"font-weight:(\d+)", f).group(1))) for f in faces}
    # the weights this stylesheet actually uses, so nothing is faux-bolded
    assert declared >= {("IBM Plex Sans", w) for w in (400, 500, 600)}
    assert declared >= {("IBM Plex Mono", w) for w in (400, 500)}
    for f in faces:
        assert "font-display:swap" in f
        src = re.search(r'url\("\.\./fonts/([^"]+)"\)', f).group(1)
        path = os.path.join(STATIC, "fonts", src)
        assert os.path.isfile(path), src
        with open(path, "rb") as fh:
            assert fh.read(4) == b"wOF2", f"{src} is not a WOFF2 file"
    for family in ("IBMPlexSans", "IBMPlexMono"):
        lic = _read("fonts", f"{family}-OFL.txt")
        assert "SIL OPEN FONT LICENSE Version 1.1" in lic
    # a system fallback follows Plex in both stacks
    assert re.search(r'--sans:"IBM Plex Sans",[^;]*sans-serif', css)
    assert re.search(r'--mono:"IBM Plex Mono",[^;]*monospace', css)


def test_every_static_file_is_package_data():
    """A file missing from package-data only goes missing after `pip install`."""
    with open(os.path.join(ROOT, "pyproject.toml"), "rb") as fh:
        patterns = tomllib.load(fh)["tool"]["setuptools"]["package-data"]["cipherguard.api"]
    api_dir = os.path.dirname(STATIC)
    unpackaged = []
    for dirpath, _dirs, files in os.walk(STATIC):
        for name in files:
            rel = os.path.relpath(os.path.join(dirpath, name), api_dir).replace(os.sep, "/")
            if not any(fnmatch.fnmatch(rel, p) for p in patterns):
                unpackaged.append(rel)
    assert not unpackaged, unpackaged


def test_static_export_ships_fonts_and_glossary(tmp_path):
    from cipherguard.export.static_site import export
    from cipherguard.lab import pcapgen

    caps = tmp_path / "caps"
    caps.mkdir()
    pcapgen.scenario_hardened(str(caps / "hardened.pcap"))
    out = tmp_path / "site"
    export(capture_dir=str(caps), out_dir=str(out), model_dir="models", verbose=False)
    for name in os.listdir(os.path.join(STATIC, "fonts")):
        assert (out / "fonts" / name).is_file(), name
    assert (out / "glossary.json").is_file()
    html = (out / "index.html").read_text(encoding="utf-8")
    assert not (_hosts(html) - LOOPBACK)
