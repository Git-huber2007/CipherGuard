"""Pull self-contained modules out of the dashboard scripts so Node can run them.

The dashboard is a handful of classic scripts loaded in order (js/core.js to
js/main.js) that share one global scope. Its testable parts are written as
`const Name = (() => { ... })();` modules with no DOM access at definition
time, so a test can evaluate one (plus the modules it depends on) under Node
with a small stub for the page.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Any

STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cipherguard", "api", "static")

NODE = shutil.which("node")

ESC = (
    "const esc = s => String(s == null ? '' : s).replace(/[&<>\"']/g,\n"
    "  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));\n"
)


def dashboard_scripts() -> list[str]:
    """The dashboard's script files, in the order index.html loads them."""
    with open(os.path.join(STATIC, "index.html"), encoding="utf-8") as fh:
        html = fh.read()
    names = re.findall(r'<script src="/static/js/([\w.-]+)" defer></script>', html)
    assert names and names[0] == "core.js" and names[-1] == "main.js", names
    return names


def dashboard_js() -> str:
    """Every dashboard script concatenated in load order: what the page runs."""
    parts = []
    for name in dashboard_scripts():
        with open(os.path.join(STATIC, "js", name), encoding="utf-8") as fh:
            parts.append(fh.read())
    return "\n".join(parts)


def module(name: str, js: str | None = None) -> str:
    js = js if js is not None else dashboard_js()
    start = js.index(f"const {name} = (() => {{")
    return js[start : js.index("})();", start) + len("})();")]


def function(name: str, js: str | None = None) -> str:
    """A top-level `function name(...)` or `async function name(...)`, whole."""
    js = js if js is not None else dashboard_js()
    for prefix in (f"async function {name}(", f"function {name}("):
        if prefix in js:
            start = js.index(prefix)
            depth, i = 0, js.index("{", start)
            for j in range(i, len(js)):
                depth += {"{": 1, "}": -1}.get(js[j], 0)
                if depth == 0:
                    return js[start : j + 1]
    raise KeyError(name)


def run_node(script: str, data: Any = None) -> Any:
    proc = subprocess.run(
        ["node", "-e", script], input=json.dumps(data), capture_output=True, text=True, encoding="utf-8", timeout=30
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout) if proc.stdout.strip() else None
