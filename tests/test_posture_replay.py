"""Posture replay: a link's recorded history, as the detector saw it.

Two properties matter more than the pictures. The replay only ever reads the
store — a GET that migrated or wrote to the sensor's database would be a page
view with side effects on the evidence. And every mark it draws is a verdict
record() actually reached, not one re-derived afterwards.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from cipherguard.api.server import STATIC_DIR
from cipherguard.intel.baseline import VERDICTS, BaselineStore
from tests.jsmodules import module
from tests.test_unattended import STRONG, WEAK, _assessment, _session

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
T0 = datetime(2026, 9, 1, 6, 0, tzinfo=timezone.utc)
PEER1 = "10.8.1.1|10.8.1.2"
needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _digest(path) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _watch_demo(db: str, captures: str) -> list[int]:
    """The documented demo: watch hardened, then downgrade, into one store."""
    from cipherguard.cli import main

    codes = []
    for name in ("hardened.pcap", "downgrade.pcap"):
        with contextlib.redirect_stdout(io.StringIO()):
            codes.append(main(["watch", os.path.join(captures, name), "--db", db]))
    return codes


@pytest.fixture
def demo_db(tmp_path) -> str:
    from cipherguard.lab import pcapgen

    caps = tmp_path / "caps"
    caps.mkdir()
    pcapgen.scenario_hardened(str(caps / "hardened.pcap"))
    pcapgen.scenario_downgrade(str(caps / "downgrade.pcap"))
    db = str(tmp_path / "f.db")
    assert _watch_demo(db, str(caps)) == [0, 3]
    return db


# ---------------------------------------------------------------------------
# Verdicts are recorded, and the rules that produce them are unchanged
# ---------------------------------------------------------------------------


def test_the_demo_sequence_replays_as_128_to_80(demo_db):
    with BaselineStore.open_readonly(demo_db) as store:
        (link,) = store.fleet()
        replay = store.replay(link["peer_key"])

    first, second = replay["observations"]
    assert first["verdict"] == "new" and first["classical_bits"] == 128
    assert second["verdict"] == "downgrade"
    assert (second["baseline_bits"], second["classical_bits"], second["delta_bits"]) == (128, 80, -48)
    assert second["baseline_transforms"] == first["transforms"]
    assert second["transforms"] != first["transforms"]
    assert replay["baseline"]["classical_bits"] == 128      # a downgrade never lowers it


@pytest.mark.no_model
def test_every_verdict_is_what_record_decided(tmp_path):
    """One link through each branch of record(): the stored verdicts must match
    the drifts it returned, including the ones that return no drift at all."""
    seq = [(WEAK, "new"), (STRONG, "unconfirmed"), (STRONG, "improvement"),
           (STRONG, "steady"), (WEAK, "downgrade"), (STRONG, "steady")]
    returned = []
    with BaselineStore(str(tmp_path / "b.db")) as store:
        for i, (tx, _) in enumerate(seq):
            returned.append([d.kind for d in store.record(
                _assessment(f"w{i}.pcap", _session(1, tx)), now=T0 + timedelta(minutes=i))])
        store.record(_assessment("spoof.pcap", _session(9, WEAK)), max_new_peers=0,
                     now=T0 + timedelta(minutes=10))
        replay = store.replay(PEER1)
        withheld = store.conn.execute(
            "SELECT verdict FROM observations WHERE capture = 'spoof.pcap'").fetchone()[0]

    assert [o["verdict"] for o in replay["observations"]] == [v for _, v in seq]
    assert returned == [["new"], [], ["improvement"], [], ["downgrade"], []]
    assert withheld == "withheld"
    assert set(VERDICTS) >= {o["verdict"] for o in replay["observations"]} | {"withheld"}


@pytest.mark.no_model
def test_old_stores_gain_verdict_columns_without_invented_verdicts(tmp_path):
    path = str(tmp_path / "old.db")
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE observations (id INTEGER PRIMARY KEY AUTOINCREMENT,
            peer_key TEXT NOT NULL, observed_at TEXT NOT NULL, capture TEXT NOT NULL,
            ike_version TEXT, vendor_family TEXT, classical_bits INTEGER NOT NULL,
            quantum_bits INTEGER NOT NULL, dh_group INTEGER, transforms TEXT NOT NULL,
            score INTEGER NOT NULL);
        CREATE TABLE baselines (peer_key TEXT PRIMARY KEY,
            best_classical_bits INTEGER NOT NULL, best_quantum_bits INTEGER NOT NULL,
            best_transforms TEXT NOT NULL, best_seen_at TEXT NOT NULL,
            first_seen_at TEXT NOT NULL, observations INTEGER NOT NULL DEFAULT 1);
        INSERT INTO observations VALUES
            (1, 'p', '2026-01-01T00:00:00+00:00', 'a', 'IKEv2', '', 128, 0, 19, '["x"]', 90);
        INSERT INTO baselines VALUES ('p', 128, 0, '["x"]',
            '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00', 1);
    """)
    conn.commit()
    conn.close()

    # read-only first: an old store is readable as it is, and left as it is
    before = _digest(path)
    with BaselineStore.open_readonly(path) as store:
        (obs,) = store.replay("p")["observations"]
    assert obs["verdict"] is None and obs["delta_bits"] is None
    assert _digest(path) == before

    # opening it for writing migrates it; history keeps no made-up verdicts
    with BaselineStore(path) as store:
        cols = {r["name"] for r in store.conn.execute("PRAGMA table_info(observations)")}
        assert {"verdict", "baseline_bits", "baseline_transforms"} <= cols
        assert store.replay("p")["observations"][0]["verdict"] is None


# ---------------------------------------------------------------------------
# The replay reads, and only reads
# ---------------------------------------------------------------------------


def test_replay_and_fleet_leave_the_store_byte_for_byte_unchanged(demo_db):
    before = _digest(demo_db)
    with BaselineStore.open_readonly(demo_db) as store:
        for link in store.fleet():
            store.replay(link["peer_key"])
        store.summary()
        with pytest.raises(sqlite3.OperationalError):
            store.conn.execute("DELETE FROM observations")
    assert _digest(demo_db) == before


@pytest.mark.no_model
def test_read_only_open_never_creates_a_store(tmp_path):
    missing = tmp_path / "nope" / "f.db"
    with pytest.raises(FileNotFoundError):
        BaselineStore.open_readonly(str(missing))
    assert not missing.parent.exists()


@pytest.mark.no_model
def test_only_links_with_a_baseline_can_be_replayed(tmp_path):
    """A withheld peer is what a spoofed address looks like; its rows must not
    be reachable through the replay."""
    with BaselineStore(str(tmp_path / "b.db")) as store:
        store.record(_assessment("real.pcap", _session(1, STRONG)))
        store.record(_assessment("spoof.pcap", _session(2, WEAK)), max_new_peers=0)
        assert store.replay(PEER1)["observations"]
        for key in ("10.8.2.1|10.8.2.2", "nobody", "' OR 1=1 --"):
            with pytest.raises(KeyError):
                store.replay(key)


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


def _client(db: str, **kw):
    from fastapi.testclient import TestClient

    from cipherguard.api.server import create_app

    return TestClient(create_app(baseline_db=db, **kw))


def test_history_endpoint_returns_a_known_link(demo_db):
    client = _client(demo_db)
    before = _digest(demo_db)
    links = client.get("/api/fleet").json()["links"]
    r = client.get("/api/fleet/history", params={"peer": links[0]["peer_key"]})
    assert r.status_code == 200
    body = r.json()
    assert [o["verdict"] for o in body["observations"]] == ["new", "downgrade"]
    assert body["observations"][1]["delta_bits"] == -48
    assert _digest(demo_db) == before, "a GET modified the baseline store"


def test_history_endpoint_takes_only_a_peer_key_that_exists(demo_db, tmp_path):
    client = _client(demo_db)
    assert client.get("/api/fleet/history").status_code == 422
    assert client.get("/api/fleet/history", params={"peer": "10.0.0.1|10.0.0.2"}).status_code == 404
    assert client.get("/api/fleet/history", params={"peer": "x" * 257}).status_code == 400
    assert client.get("/api/fleet/history", params={"peer": "a\nb"}).status_code == 400

    # the store path is fixed at construction: a db parameter is ignored, and
    # naming a path through it neither reads nor creates anything there
    elsewhere = tmp_path / "probe" / "other.db"
    links = client.get("/api/fleet").json()["links"]
    r = client.get("/api/fleet/history",
                   params={"peer": links[0]["peer_key"], "db": str(elsewhere)})
    assert r.status_code == 200 and not elsewhere.parent.exists()


@pytest.mark.no_model
def test_history_endpoint_without_a_store(tmp_path):
    db = tmp_path / "absent.db"
    client = _client(str(db))
    assert client.get("/api/fleet/history", params={"peer": "a|b"}).status_code == 404
    assert client.get("/api/fleet").json()["tracked"] is False
    assert not db.exists(), "reading created the store"


def test_history_endpoint_is_behind_the_token(demo_db):
    client = _client(demo_db, auth_token="s3cret")
    assert client.get("/api/fleet/history", params={"peer": "a|b"}).status_code == 401
    ok = client.get("/api/fleet/history", params={"peer": "a|b"},
                    headers={"Authorization": "Bearer s3cret"})
    assert ok.status_code == 404        # authenticated, and still only known links


@pytest.mark.no_model
def test_fleet_endpoint_no_longer_migrates_on_read(tmp_path):
    """Regression: /api/fleet opened the store with the normal constructor,
    which runs the schema script and ALTER TABLE migrations — a page view
    rewrote the sensor's database."""
    path = str(tmp_path / "old.db")
    with BaselineStore(path) as store:
        store.record(_assessment("w.pcap", _session(1, STRONG)))
        store.conn.execute("ALTER TABLE observations DROP COLUMN verdict")
        store.conn.commit()
    before = _digest(path)
    assert _client(path).get("/api/fleet").json()["tracked"] is True
    assert _digest(path) == before


# ---------------------------------------------------------------------------
# Static build
# ---------------------------------------------------------------------------


@pytest.mark.no_model
def test_static_export_bakes_the_demo_from_real_watch_runs(tmp_path):
    from cipherguard.export.static_site import export
    from cipherguard.lab import pcapgen

    caps = tmp_path / "caps"
    caps.mkdir()
    pcapgen.scenario_mixed_backbone(str(caps / "backbone.pcap"))   # demo captures absent
    out = tmp_path / "site"
    export(capture_dir=str(caps), out_dir=str(out), model_dir="models", verbose=False)

    demo = json.loads((out / "data" / "fleet_demo.json").read_text(encoding="utf-8"))
    assert [c["exit_code"] for c in demo["commands"]] == [0, 3]
    assert all(c["capture_source"] == "generated by the lab scenario" for c in demo["commands"])
    (link,) = demo["fleet"]["links"]
    assert link["degraded"] and (link["best_classical_bits"], link["current_bits"]) == (128, 80)
    obs = demo["histories"][link["peer_key"]]["observations"]
    assert [o["verdict"] for o in obs] == ["new", "downgrade"]

    html = (out / "index.html").read_text(encoding="utf-8")
    assert 'id="replay-panel"' in html
    assert "invisible in either capture alone" in html


# ---------------------------------------------------------------------------
# Front end, run under Node
# ---------------------------------------------------------------------------


def _read(*parts: str) -> str:
    with open(os.path.join(STATIC_DIR, *parts), encoding="utf-8") as fh:
        return fh.read()


def _module() -> str:
    js = _read("js", "dashboard.js")
    start = js.index("const PostureReplay = (() => {")
    return js[start: js.index("})();", start) + len("})();")]


_PRELUDE = r"""
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function makeEl(id){
  const attrs = {};
  return { id, textContent: "", innerHTML: "", hidden: false, disabled: false, value: "",
    max: "0", listeners: {}, attrs,
    setAttribute(k, v){ attrs[k] = v; }, getAttribute(k){ return attrs[k]; },
    addEventListener(t, f){ (this.listeners[t] = this.listeners[t] || []).push(f); } };
}
const els = {};
const $ = id => els[id] || (els[id] = makeEl(id));
let tickFn = null, cleared = 0;
global.setInterval = (fn, ms) => { tickFn = fn; return 1; };
global.clearInterval = () => { cleared++; tickFn = null; };
const window = { addEventListener(){} };
const staticMode = { active: false };
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const out = x => process.stdout.write(JSON.stringify(x));
"""


def _node(body: str, data) -> Any:
    # the replay formats bits through the shared Fmt module
    proc = subprocess.run(["node", "-e", _PRELUDE + module("Fmt") + "\n" + _module() + "\n" + body],
                          input=json.dumps(data), capture_output=True, text=True,
                          encoding="utf-8", timeout=30)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _long_history(tmp_path) -> dict:
    seq = [WEAK, STRONG, STRONG, STRONG, WEAK, STRONG, WEAK]
    with BaselineStore(str(tmp_path / "long.db")) as store:
        for i, tx in enumerate(seq):
            store.record(_assessment(f"w{i}.pcap", _session(1, tx)), now=T0 + timedelta(minutes=i))
        return store.replay(PEER1)


@pytest.mark.no_model
@needs_node
def test_chart_draws_one_mark_per_observation_and_marks_downgrades(tmp_path):
    hist = _long_history(tmp_path)
    svg = _node("out(PostureReplay.chartSVG(input.observations, 720));", hist)

    circles = re.findall(r'<circle class="rp-mark[^"]*"', svg)
    triangles = re.findall(r'<path class="rp-mark rp-down"', svg)
    n = len(hist["observations"])
    downs = [o for o in hist["observations"] if o["verdict"] == "downgrade"]
    assert len(circles) + len(triangles) == n
    assert len(triangles) == len(downs) == 2
    assert len(re.findall(r'class="rp-drop"', svg)) == 2
    assert svg.count("−48") == 2                          # the bit delta, labelled
    assert len(re.findall(r'rp-unconf', svg)) == 1             # the unpromoted sighting
    assert f"over {n} observations, 2 downgrades" in svg
    # the selection cursor sits behind the data, never drawn over it
    assert svg.index('class="rp-cursor"') < svg.index('class="rp-line"')


@pytest.mark.no_model
@needs_node
def test_downgrade_detail_sets_the_transform_sets_side_by_side(tmp_path):
    hist = _long_history(tmp_path)
    i = next(i for i, o in enumerate(hist["observations"]) if o["verdict"] == "downgrade")
    html = _node("out(PostureReplay.detailHTML(input.h.observations, input.i, input.h.verdicts));",
                 {"h": hist, "i": i})
    o = hist["observations"][i]
    assert "Downgrade: 128 → 80 bits (−48)" in html
    before, after = html.split('<div class="rp-col">')[1:3]
    assert "Baseline · 128 bits" in before and "Negotiated here · 80 bits" in after
    for t in o["baseline_transforms"]:
        assert t in before
    for t in o["transforms"]:
        assert t in after
    # changed items are marked in text, not only by style
    assert "(not negotiated here)" in before and "(not in the baseline)" in after


@pytest.mark.no_model
@needs_node
def test_play_steps_through_the_history_and_stops_at_the_end(tmp_path):
    hist = _long_history(tmp_path)
    got = _node("""
      PostureReplay.show(input);
      const start = PostureReplay.index;
      PostureReplay.play();                      // at the latest downgrade: restarts from 1
      const seen = [PostureReplay.index];
      while (tickFn){ tickFn(); seen.push(PostureReplay.index); }
      const ended = { playing: PostureReplay.playing, label: $("replay-play").textContent,
                      pressed: $("replay-play").attrs["aria-pressed"] };
      out({ start, seen, ended, valuetext: $("replay-scrub").attrs["aria-valuetext"],
            pos: $("replay-pos").textContent });
    """, hist)
    n = len(hist["observations"])
    assert got["start"] == n - 1                     # opens on the most recent downgrade
    assert got["seen"] == list(range(n))             # one step per observation, in order
    assert got["ended"] == {"playing": False, "label": "Play", "pressed": "false"}
    assert got["pos"] == f"{n} / {n}"
    assert got["valuetext"].startswith(f"Observation {n} of {n}: 80 bits, downgrade")


@pytest.mark.no_model
@needs_node
def test_a_single_observation_cannot_play(tmp_path):
    with BaselineStore(str(tmp_path / "b.db")) as store:
        store.record(_assessment("w.pcap", _session(1, STRONG)))
        hist = store.replay(PEER1)
    got = _node("PostureReplay.show(input); PostureReplay.play();"
                "out({disabled: $('replay-play').disabled, playing: PostureReplay.playing});", hist)
    assert got == {"disabled": True, "playing": False}


@pytest.mark.no_model
def test_panel_copy_and_reduced_motion():
    html = _read("index.html")
    panel = html[html.index('id="replay-panel"'):]
    panel = panel[: panel.index("</section>")]
    assert "This change is invisible in either capture alone" in panel
    assert 'type="range" id="replay-scrub"' in panel and 'id="replay-play"' in panel

    css = _read("css", "dashboard.css")
    reduced = [m for m in re.findall(r"@media \(prefers-reduced-motion:reduce\)\{(.*?)\}\s*\}", css, re.S)
               if "rp-cursor" in m]
    assert reduced and "transition:none" in reduced[0]
    for rule in re.findall(r"\.rp-[^{]*\{([^}]*)\}", css):
        assert "animation" not in rule
