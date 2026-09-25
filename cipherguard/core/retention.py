"""Evidence retention for window captures.

Shared by both sensor loops — `cipherguard sensor` in cli.py and the library
loop in capture/sensor.py — so that neither can drift into keeping captures the
other would have pruned.
"""

from __future__ import annotations

import os

EVIDENCE_PREFIX = "window-"
EVIDENCE_SUFFIX = ".pcap"


def prune_evidence(
    directory: str, keep: int, max_bytes: int, protect: str | None = None
) -> tuple[int, int]:
    """Enforce the evidence retention policy, oldest first.

    A sensor is a long-running process writing one capture per window. Without a
    retention policy that is unbounded growth on the sensor's own disk — at
    300-second windows a 50 Mbps link produces about 540 GB a day, so the host
    fills in hours and the monitoring dies. Retention is therefore part of the
    feature, not an operational afterthought.

    Both ceilings apply: a count keeps the recent history predictable, and a
    byte cap is what actually protects the disk, because window size varies with
    link load and a count alone cannot bound it.

    Only `window-*.pcap` files are considered, so an operator's own files in
    the directory are never touched; a sensor must name its captures to match.

    `protect` is the capture behind the most recent assessment, and is never
    removed. Without it a single window larger than `max_bytes` deleted itself
    the moment it had been assessed, so the latest finding had no evidence.
    The ceiling is then exceeded by that one window, which `--max-window-mb`
    bounds.
    """
    try:
        files = sorted(
            (os.path.join(directory, n) for n in os.listdir(directory)
             if n.startswith(EVIDENCE_PREFIX) and n.endswith(EVIDENCE_SUFFIX)),
            key=os.path.getmtime,
        )
    except OSError:
        return 0, 0

    guarded = os.path.normcase(os.path.abspath(protect)) if protect else None

    def drop_oldest() -> bool:
        for i, f in enumerate(files):
            if os.path.normcase(os.path.abspath(f)) == guarded:
                continue
            try:
                os.remove(f)
            except OSError:
                return False
            files.pop(i)
            return True
        return False

    removed = 0
    while len(files) > keep and drop_oldest():
        removed += 1

    def total() -> int:
        return sum(os.path.getsize(f) for f in files if os.path.exists(f))

    while files and max_bytes and total() > max_bytes and drop_oldest():
        removed += 1

    return removed, total()
